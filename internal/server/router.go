package server

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"lancollab/internal/protocol"
	"lancollab/internal/transport"
)

const (
	chatQueueSize = 1024 // stream-1 messages waiting for one recipient

	// fileQueueLimit is a memory safety net per recipient (about 96 MiB); only the overflowing transfer fails.
	fileQueueLimit = 98304
)

// relayItem is one hop-2 packet waiting to be sent to a recipient.
type relayItem struct {
	hdr       protocol.UDPHeader
	plaintext []byte
}

// relayQueue is one recipient's file FIFO; push never blocks, so a slow recipient never stalls others.
type relayQueue struct {
	mu     sync.Mutex
	items  []relayItem
	notify chan struct{}
	limit  int
}

func newRelayQueue(limit int) *relayQueue {
	return &relayQueue{notify: make(chan struct{}, 1), limit: limit}
}

// push appends it, or returns false when the queue is at its limit and force is not set.
func (q *relayQueue) push(it relayItem, force bool) bool {
	q.mu.Lock()
	if !force && len(q.items) >= q.limit {
		q.mu.Unlock()
		return false
	}
	q.items = append(q.items, it)
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

func (q *relayQueue) pop() (relayItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return relayItem{}, false
	}
	it := q.items[0]
	q.items[0] = relayItem{}
	q.items = q.items[1:]
	if len(q.items) == 0 {
		q.items = nil
	}
	return it, true
}

// recipient owns one client's chat and file queues, each with its own forwarder, so files never delay chat.
type recipient struct {
	sess  *ClientSession
	chatQ chan relayItem
	fileQ *relayQueue
	done  chan struct{}
	once  sync.Once
}

func (rc *recipient) stop() { rc.once.Do(func() { close(rc.done) }) }

type seqKey struct {
	sender    uint16
	recipient uint16
}

// fileKey identifies one transfer; stream IDs are unique per sender session and user IDs are never reused.
type fileKey struct {
	sender uint16
	stream uint16
}

// Router relays hop by hop: decrypt with Key_A (hop 1), re-encrypt with Key_B and send reliably (hop 2).
type Router struct {
	sm   *SessionManager
	ep   *transport.RDTEndpoint
	logf func(format string, args ...any)

	mu          sync.Mutex
	recipients  map[uint16]*recipient
	chatSeq     map[seqKey]uint32
	failedFiles map[fileKey]struct{} // transfers already reported to their sender as failed
	fileLimit   int

	wg sync.WaitGroup
}

// NewRouter creates a router; call Start to begin relaying.
func NewRouter(sm *SessionManager, ep *transport.RDTEndpoint, logf func(format string, args ...any)) *Router {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Router{
		sm:          sm,
		ep:          ep,
		logf:        logf,
		recipients:  make(map[uint16]*recipient),
		chatSeq:     make(map[seqKey]uint32),
		failedFiles: make(map[fileKey]struct{}),
		fileLimit:   fileQueueLimit,
	}
}

// SetFileQueueLimit changes the per-recipient safety limit (in packets). Call before Start.
func (r *Router) SetFileQueueLimit(n int) {
	if n > 0 {
		r.mu.Lock()
		r.fileLimit = n
		r.mu.Unlock()
	}
}

// Start installs the heartbeat hook and the two relay goroutines.
func (r *Router) Start() {
	r.ep.SetInboundHook(r.onInbound)
	r.wg.Add(2)
	go r.consumeChatStream()
	go r.consumeFiles()
}

// onInbound treats any authenticated packet as a sign of life and records the client's current UDP address.
func (r *Router) onInbound(pkt *protocol.UDPPacket, _ []byte, from *net.UDPAddr) {
	r.sm.UpdateHeartbeat(pkt.Header.SenderID, from)
}

// AddRecipient starts the forwarders of a newly signed-in client.
func (r *Router) AddRecipient(sess *ClientSession) {
	r.mu.Lock()
	rc := &recipient{
		sess:  sess,
		chatQ: make(chan relayItem, chatQueueSize),
		fileQ: newRelayQueue(r.fileLimit),
		done:  make(chan struct{}),
	}
	if old := r.recipients[sess.UserID]; old != nil {
		old.stop()
	}
	r.recipients[sess.UserID] = rc
	r.mu.Unlock()
	r.wg.Add(2)
	go r.runForwarder(rc, rc.chatQ)
	go r.runFileForwarder(rc)
}

// RemoveRecipient stops the forwarders of a client that left and forgets its counters.
func (r *Router) RemoveRecipient(userID uint16) {
	r.mu.Lock()
	rc := r.recipients[userID]
	delete(r.recipients, userID)
	// Drop counters toward the departed client, but keep those from it so a later failure FILE_DONE is not seen as a duplicate.
	for k := range r.chatSeq {
		if k.recipient == userID {
			delete(r.chatSeq, k)
		}
	}
	for k := range r.failedFiles {
		if k.sender == userID {
			delete(r.failedFiles, k)
		}
	}
	r.mu.Unlock()
	if rc != nil {
		rc.stop()
	}
}

// Stop stops every forwarder (server shutdown).
func (r *Router) Stop() {
	r.mu.Lock()
	for id, rc := range r.recipients {
		rc.stop()
		delete(r.recipients, id)
	}
	r.mu.Unlock()
}

// Wait blocks until all router goroutines have exited (after Stop and endpoint Close).
func (r *Router) Wait() { r.wg.Wait() }

func (r *Router) consumeChatStream() {
	defer r.wg.Done()
	for pkt := range r.ep.ChatChan() {
		r.relayChatStream(pkt)
	}
}

func (r *Router) consumeFiles() {
	defer r.wg.Done()
	for pkt := range r.ep.FileChan() {
		r.relayFile(pkt)
	}
}

func (r *Router) relayChatStream(pkt transport.DeliveredPacket) {
	h := pkt.Header
	sender, ok := r.sm.Get(h.SenderID)
	if !ok {
		return
	}
	switch h.MsgType {
	case protocol.MsgChat:
		var chat protocol.ChatPayload
		if err := json.Unmarshal(pkt.Plaintext, &chat); err != nil || strings.TrimSpace(chat.Text) == "" {
			r.logf("dropping malformed chat from #%d", h.SenderID)
			return
		}
		chat.From = sender.Username // the server, not the client, vouches for the sender name
		if chat.TS == 0 {
			chat.TS = time.Now().UnixMilli()
		}
		body, err := protocol.MarshalJSONCompact(chat)
		if err != nil || len(body) > protocol.MaxChunkSize {
			r.logf("dropping oversized chat from #%d", h.SenderID)
			return
		}
		if h.TargetID == protocol.BroadcastTarget {
			for _, id := range r.sm.OnlineIDs() {
				if id != h.SenderID {
					r.enqueueChatStream(h.SenderID, id, protocol.MsgChat, protocol.FlagEOM|protocol.FlagBcast, protocol.BroadcastTarget, body)
				}
			}
			return
		}
		if h.TargetID == h.SenderID || h.TargetID == protocol.ServerID {
			return
		}
		r.enqueueChatStream(h.SenderID, h.TargetID, protocol.MsgChat, protocol.FlagEOM, h.TargetID, body)

	case protocol.MsgFileDone:
		if h.TargetID == protocol.BroadcastTarget || h.TargetID == protocol.ServerID || h.TargetID == h.SenderID {
			return
		}
		r.enqueueChatStream(h.SenderID, h.TargetID, protocol.MsgFileDone, protocol.FlagEOM, h.TargetID, pkt.Plaintext)
	}
}

// enqueueChatStream assigns the next hop-2 seq and queues under one lock, so no seq number is ever skipped.
func (r *Router) enqueueChatStream(sender, recipientID uint16, msgType, flags uint8, target uint16, body []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	rc := r.recipients[recipientID]
	if rc == nil {
		return false
	}
	if len(rc.chatQ) >= cap(rc.chatQ) {
		r.logf("chat queue to #%d is full; dropping a message from #%d", recipientID, sender)
		return false
	}
	k := seqKey{sender: sender, recipient: recipientID}
	seq, ok := r.chatSeq[k]
	if !ok {
		seq = protocol.InitialSeq(protocol.StreamChat)
	}
	r.chatSeq[k] = seq + 1
	rc.chatQ <- relayItem{
		hdr: protocol.UDPHeader{
			MsgType:  msgType,
			Flags:    flags,
			StreamID: protocol.StreamChat,
			SenderID: sender,
			TargetID: target,
			SeqNum:   seq,
		},
		plaintext: body,
	}
	return true
}

// relayFile queues one file packet and never blocks, because this goroutine serves every user's files.
func (r *Router) relayFile(pkt transport.DeliveredPacket) {
	h := pkt.Header
	if h.TargetID == protocol.BroadcastTarget || h.TargetID == protocol.ServerID || h.TargetID == h.SenderID {
		return // files are unicast only
	}
	fk := fileKey{sender: h.SenderID, stream: h.StreamID}
	r.mu.Lock()
	_, failed := r.failedFiles[fk]
	rc := r.recipients[h.TargetID]
	r.mu.Unlock()
	if failed {
		return // the sender has already been told; drop the rest of this transfer
	}
	if rc == nil {
		r.failFile(h, "the recipient is offline", nil)
		return
	}
	item := relayItem{
		hdr: protocol.UDPHeader{
			MsgType:  h.MsgType,
			Flags:    h.Flags &^ protocol.FlagRetrans,
			StreamID: h.StreamID,
			SenderID: h.SenderID,
			TargetID: h.TargetID,
			SeqNum:   h.SeqNum,
		},
		plaintext: pkt.Plaintext,
	}
	if !rc.fileQ.push(item, false) {
		r.failFile(h, "the recipient is too slow to receive this file", rc)
	}
}

// failFile tells the sender once and queues a FILE_END to an online recipient so it stops waiting.
func (r *Router) failFile(h protocol.UDPHeader, reason string, rc *recipient) {
	fk := fileKey{sender: h.SenderID, stream: h.StreamID}
	r.mu.Lock()
	if _, done := r.failedFiles[fk]; done {
		r.mu.Unlock()
		return
	}
	r.failedFiles[fk] = struct{}{}
	r.mu.Unlock()

	r.logf("file transfer #%d from #%d to #%d failed: %s", h.StreamID, h.SenderID, h.TargetID, reason)
	r.notifyFileFailed(h, reason)
	if rc != nil {
		rc.fileQ.push(relayItem{hdr: protocol.UDPHeader{
			MsgType:  protocol.MsgFileEnd,
			Flags:    protocol.FlagEOM,
			StreamID: h.StreamID,
			SenderID: h.SenderID,
			TargetID: h.TargetID,
			SeqNum:   h.SeqNum,
		}}, true)
	}
}

// notifyFileFailed sends the sender a failure FILE_DONE that appears to come from the recipient.
func (r *Router) notifyFileFailed(h protocol.UDPHeader, reason string) {
	body, err := protocol.MarshalJSONCompact(protocol.FileDonePayload{StreamID: h.StreamID, OK: false, Reason: reason})
	if err != nil {
		return
	}
	r.enqueueChatStream(h.TargetID, h.SenderID, protocol.MsgFileDone, protocol.FlagEOM, h.SenderID, body)
}

// deliver sends one relayed packet on hop 2. It reports whether the forwarder must stop.
func (r *Router) deliver(rc *recipient, it relayItem) (stop bool) {
	userID := rc.sess.UserID
	addr, key, ok := r.sm.Endpoint(userID)
	if !ok {
		return true
	}
	err := r.ep.SendReliable(userID, addr, key, it.hdr, it.plaintext)
	if errors.Is(err, transport.ErrEndpointClosed) || errors.Is(err, transport.ErrPeerGone) {
		return true
	}
	if err != nil {
		r.logf("relay to #%d failed: %v", userID, err)
	}
	return false
}

func (r *Router) runForwarder(rc *recipient, q chan relayItem) {
	defer r.wg.Done()
	for {
		select {
		case <-rc.done:
			return
		case it := <-q:
			if r.deliver(rc, it) {
				return
			}
		}
	}
}

func (r *Router) runFileForwarder(rc *recipient) {
	defer r.wg.Done()
	for {
		it, ok := rc.fileQ.pop()
		if !ok {
			select {
			case <-rc.fileQ.notify:
				continue
			case <-rc.done:
				return
			}
		}
		if r.deliver(rc, it) {
			return
		}
	}
}
