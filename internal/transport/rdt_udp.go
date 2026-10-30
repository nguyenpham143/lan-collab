package transport

import (
	"errors"
	"math"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"lancollab/internal/protocol"
)

// Engine errors.
var (
	ErrEndpointClosed  = errors.New("transport: endpoint closed")
	ErrPeerGone        = errors.New("transport: peer has been removed")
	ErrNotDataMessage  = errors.New("transport: only CHAT/FILE messages on stream >= 1 are sent reliably")
	ErrNoDestination   = errors.New("transport: no destination address")
	ErrDuplicateSeqNum = errors.New("transport: sequence number already in flight")
)

// fastRetransmitThreshold is how many later ACKs trigger an early resend of an unacked packet.
const fastRetransmitThreshold = 3

// chatReserve lets stream 1 exceed cwnd by a few slots, so chat never waits behind file chunks.
const chatReserve = 4

const (
	retransmitTick    = 20 * time.Millisecond // how often unacknowledged packets are checked
	gcInterval        = time.Second           // how often idle stream state is collected
	streamIdleTimeout = 60 * time.Second      // idle file streams are forgotten after this
)

// RDTStats is a snapshot of the reliable-transport state toward one peer.
type RDTStats struct {
	RTTMillis       int64  `json:"rtt_ms"`
	RTTMicros       int64  `json:"rtt_us"`
	RTOMillis       int64  `json:"rto_ms"`
	Cwnd            int    `json:"cwnd"`
	Ssthresh        int    `json:"ssthresh"`
	PeerRwnd        int    `json:"peer_rwnd"`
	InFlight        int    `json:"in_flight"`
	Retransmissions uint64 `json:"retransmissions"`
	PacketsSent     uint64 `json:"packets_sent"`
	PacketsAcked    uint64 `json:"packets_acked"`
}

// DeliveredPacket is a verified, decrypted data packet, delivered in order for its (SenderID, StreamID).
type DeliveredPacket struct {
	Header    protocol.UDPHeader
	Plaintext []byte
	FromAddr  *net.UDPAddr
}

// KeyResolver maps a sender_id to its AES key and latest UDP address; ok=false drops the packet.
type KeyResolver func(senderID uint16) (key []byte, addr *net.UDPAddr, ok bool)

// InboundHook sees every authenticated packet on the receive goroutine and must return quickly.
type InboundHook func(pkt *protocol.UDPPacket, plaintext []byte, from *net.UDPAddr)

// pktKey identifies an in-flight packet by peer, original sender, stream and seq (the server relays many senders).
type pktKey struct {
	peer   uint16
	sender uint16
	stream uint16
	seq    uint32
}

type sendStreamKey struct {
	peer   uint16
	sender uint16
	stream uint16
}

type recvStreamKey struct {
	sender uint16
	stream uint16
}

type sentPkt struct {
	id            pktKey
	dst           *net.UDPAddr
	key           []byte
	hdr           protocol.UDPHeader
	plaintext     []byte
	firstSent     time.Time
	lastSent      time.Time
	retransmitted bool
	laterAcks     int  // ACKs seen for later packets of the same stream
	fastRetx      bool // already resent by fast retransmit
}

// peerState is per-peer state: RTT, cwnd and packets in flight across all streams.
type peerState struct {
	id               uint16
	addr             *net.UDPAddr
	rtt              *RTTEstimator
	cc               *CubicController
	lastRwnd         uint8 // last rwnd advertised by this peer on any stream (for display)
	inFlight         int
	retrans          uint64
	sent             uint64
	acked            uint64
	lastLossReaction time.Time
	gone             bool
}

// sendStream is the Selective Repeat sender window of one (peer, sender, stream).
type sendStream struct {
	base       uint32          // send_base: smallest unacknowledged sequence number
	acked      map[uint32]bool // ACKed sequence numbers >= base
	inFlight   int
	rwnd       uint8 // receive window advertised for this stream (flow control)
	lastActive time.Time
}

// recvStream is the Selective Repeat receiver window of one (sender, stream).
type recvStream struct {
	base       uint32                     // rcv_base: next sequence number to deliver
	buf        map[uint32]DeliveredPacket // out-of-order packets inside the window
	pending    int                        // delivered in order but not yet read by the application
	lastActive time.Time
}

// RDTEndpoint is reliable multiplexed UDP: sends only if cwnd (peer), rwnd (stream) and the SR window allow.
type RDTEndpoint struct {
	conn        *net.UDPConn
	keyResolver KeyResolver
	localID     atomic.Uint32
	dropRate    atomic.Uint64 // math.Float64bits of the simulated loss rate

	hookMu sync.RWMutex
	hook   InboundHook

	mu          sync.Mutex
	cond        *sync.Cond
	peers       map[uint16]*peerState
	peerByAddr  map[string]uint16
	forgotten   map[uint16]bool
	unacked     map[pktKey]*sentPkt
	sendStreams map[sendStreamKey]*sendStream
	recvStreams map[recvStreamKey]*recvStream
	closed      bool

	chatQ *deliveryQueue
	fileQ *deliveryQueue

	badPackets atomic.Uint64

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewRDTEndpoint starts the receive, timer and two delivery goroutines; the endpoint owns conn.
func NewRDTEndpoint(conn *net.UDPConn, keyResolver KeyResolver) *RDTEndpoint {
	e := &RDTEndpoint{
		conn:        conn,
		keyResolver: keyResolver,
		peers:       make(map[uint16]*peerState),
		peerByAddr:  make(map[string]uint16),
		forgotten:   make(map[uint16]bool),
		unacked:     make(map[pktKey]*sentPkt),
		sendStreams: make(map[sendStreamKey]*sendStream),
		recvStreams: make(map[recvStreamKey]*recvStream),
		chatQ:       newDeliveryQueue(),
		fileQ:       newDeliveryQueue(),
		done:        make(chan struct{}),
	}
	e.cond = sync.NewCond(&e.mu)
	e.wg.Add(4)
	go e.readLoop()
	go e.timerLoop()
	go e.runDeliverer(e.chatQ)
	go e.runDeliverer(e.fileQ)
	return e
}

// SetLocalID sets the sender_id written into ACKs (0 = server, UserID = client).
func (e *RDTEndpoint) SetLocalID(id uint16) {
	e.localID.Store(uint32(id))
}

// SetDropRate silently drops this fraction (0..1) of datagrams, for tests and demos.
func (e *RDTEndpoint) SetDropRate(rate float64) {
	if rate < 0 || math.IsNaN(rate) {
		rate = 0
	}
	if rate > 1 {
		rate = 1
	}
	e.dropRate.Store(math.Float64bits(rate))
}

// SetInboundHook installs fn as the observer of every authenticated packet.
func (e *RDTEndpoint) SetInboundHook(fn func(pkt *protocol.UDPPacket, plaintext []byte, from *net.UDPAddr)) {
	e.hookMu.Lock()
	e.hook = fn
	e.hookMu.Unlock()
}

// ChatChan delivers stream-1 packets in order per sender; closed when the endpoint closes.
func (e *RDTEndpoint) ChatChan() <-chan DeliveredPacket {
	return e.chatQ.out
}

// FileChan delivers stream >= 2 packets in order per (sender, stream); closed when the endpoint closes.
func (e *RDTEndpoint) FileChan() <-chan DeliveredPacket { return e.fileQ.out }

// Done is closed when the endpoint is closed.
func (e *RDTEndpoint) Done() <-chan struct{} { return e.done }

// LocalAddr returns the local UDP address.
func (e *RDTEndpoint) LocalAddr() *net.UDPAddr {
	addr, _ := e.conn.LocalAddr().(*net.UDPAddr)
	return addr
}

// BadPackets counts datagrams dropped as malformed, bad checksum, unknown sender or failed decryption.
func (e *RDTEndpoint) BadPackets() uint64 { return e.badPackets.Load() }

// SendUnreliable encrypts and sends one datagram with no retransmission (used for HEARTBEAT).
func (e *RDTEndpoint) SendUnreliable(dst *net.UDPAddr, key []byte, hdr protocol.UDPHeader, plaintext []byte) error {
	if e.isClosed() {
		return ErrEndpointClosed
	}
	return e.transmit(dst, key, hdr, plaintext)
}

// SendReliable blocks until all three windows allow, sends once, then retransmits until ACKed or the peer is gone.
func (e *RDTEndpoint) SendReliable(peerID uint16, dst *net.UDPAddr, key []byte, hdr protocol.UDPHeader, plaintext []byte) error {
	if !protocol.IsDataMsg(hdr.MsgType) || hdr.StreamID == protocol.StreamHeartbeat {
		return ErrNotDataMessage
	}
	if len(plaintext) > protocol.MaxChunkSize {
		return protocol.ErrPayloadTooLarge
	}
	if dst == nil {
		return ErrNoDestination
	}
	if len(key) != protocol.SessionKeySize {
		return protocol.ErrBadKeySize
	}
	hdr.Magic = protocol.Magic
	hdr.Version = protocol.Version
	hdr.Flags &^= protocol.FlagRetrans
	hdr.Rwnd = protocol.RecvWindow // informational on data packets
	sk := sendStreamKey{peer: peerID, sender: hdr.SenderID, stream: hdr.StreamID}
	pk := pktKey{peer: peerID, sender: hdr.SenderID, stream: hdr.StreamID, seq: hdr.SeqNum}

	e.mu.Lock()
	if e.forgotten[peerID] {
		e.mu.Unlock()
		return ErrPeerGone
	}
	peer := e.peerLocked(peerID, dst)
	for {
		if e.closed {
			e.mu.Unlock()
			return ErrEndpointClosed
		}
		if peer.gone {
			e.mu.Unlock()
			return ErrPeerGone
		}
		base, streamInFlight, rwnd := hdr.SeqNum, 0, uint8(protocol.RecvWindow)
		if ss := e.sendStreams[sk]; ss != nil {
			base, streamInFlight, rwnd = ss.base, ss.inFlight, ss.rwnd
		}
		limit := peer.cc.EffectiveWindow(protocol.MaxCwnd)
		if hdr.StreamID == protocol.StreamChat {
			limit += chatReserve
		}
		congestionOK := peer.inFlight < limit
		flowOK := streamInFlight < max(1, int(rwnd))
		windowOK := hdr.SeqNum < base+protocol.RecvWindow
		if congestionOK && flowOK && windowOK {
			break
		}
		e.cond.Wait()
	}
	if _, exists := e.unacked[pk]; exists {
		e.mu.Unlock()
		return ErrDuplicateSeqNum
	}
	now := time.Now()
	ss := e.sendStreams[sk]
	if ss == nil {
		ss = &sendStream{base: hdr.SeqNum, acked: make(map[uint32]bool), rwnd: protocol.RecvWindow}
		e.sendStreams[sk] = ss
	}
	ss.inFlight++
	ss.lastActive = now
	peer.inFlight++
	peer.sent++
	e.unacked[pk] = &sentPkt{
		id:        pk,
		dst:       copyAddr(dst),
		key:       key,
		hdr:       hdr,
		plaintext: append([]byte(nil), plaintext...),
		firstSent: now,
		lastSent:  now,
	}
	e.mu.Unlock()

	// A failed write is not fatal: the packet stays unacked and the timer resends it.
	_ = e.transmit(dst, key, hdr, plaintext)
	return nil
}

// ForgetPeer drops all state for peerID; blocked and later sends fail with ErrPeerGone until AllowPeer.
func (e *RDTEndpoint) ForgetPeer(peerID uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.forgotten[peerID] = true
	if p := e.peers[peerID]; p != nil {
		p.gone = true
		delete(e.peers, peerID)
	}
	for addr, id := range e.peerByAddr {
		if id == peerID {
			delete(e.peerByAddr, addr)
		}
	}
	for k := range e.unacked {
		if k.peer == peerID {
			delete(e.unacked, k)
		}
	}
	for k := range e.sendStreams {
		if k.peer == peerID {
			delete(e.sendStreams, k)
		}
	}
	for k := range e.recvStreams {
		if k.sender == peerID {
			delete(e.recvStreams, k)
		}
	}
	e.cond.Broadcast()
}

// AllowPeer lifts a previous ForgetPeer, for example when a node ID is reused.
func (e *RDTEndpoint) AllowPeer(peerID uint16) {
	e.mu.Lock()
	delete(e.forgotten, peerID)
	e.mu.Unlock()
}

// Stats returns the transport statistics toward peerID.
func (e *RDTEndpoint) Stats(peerID uint16) RDTStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.peers[peerID]
	if p == nil {
		return RDTStats{
			RTOMillis: protocol.InitialRTO.Milliseconds(),
			Cwnd:      int(protocol.InitialCwnd),
			Ssthresh:  int(protocol.InitialSsthresh),
			PeerRwnd:  protocol.RecvWindow,
		}
	}
	est := p.rtt.EstimatedRTT()
	return RDTStats{
		RTTMillis:       est.Milliseconds(),
		RTTMicros:       est.Microseconds(),
		RTOMillis:       p.rtt.RTO().Milliseconds(),
		Cwnd:            int(p.cc.Cwnd()),
		Ssthresh:        int(p.cc.Ssthresh()),
		PeerRwnd:        int(p.lastRwnd),
		InFlight:        p.inFlight,
		Retransmissions: p.retrans,
		PacketsSent:     p.sent,
		PacketsAcked:    p.acked,
	}
}

// Close stops all goroutines and the socket; safe to call twice, but never from an InboundHook.
func (e *RDTEndpoint) Close() error {
	var err error
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		e.cond.Broadcast()
		e.mu.Unlock()
		close(e.done)
		err = e.conn.Close()
		e.wg.Wait()
	})
	return err
}

// ========================= Helpers =========================

// peerLocked returns (creating if needed) peerID's state and records dst; e.mu must be held.
func (e *RDTEndpoint) peerLocked(peerID uint16, dst *net.UDPAddr) *peerState {
	p := e.peers[peerID]
	if p == nil {
		p = &peerState{
			id:       peerID,
			rtt:      NewRTTEstimator(),
			cc:       NewCubicController(),
			lastRwnd: protocol.RecvWindow,
		}
		e.peers[peerID] = p
	}
	if dst != nil {
		if p.addr == nil || p.addr.String() != dst.String() {
			p.addr = copyAddr(dst)
		}
		e.peerByAddr[dst.String()] = peerID
	}
	return p
}

// transmit encrypts, frames and writes one datagram (subject to simulated loss).
func (e *RDTEndpoint) transmit(dst *net.UDPAddr, key []byte, hdr protocol.UDPHeader, plaintext []byte) error {
	if dst == nil {
		return ErrNoDestination
	}
	hdr.Magic = protocol.Magic
	hdr.Version = protocol.Version
	enc, err := protocol.EncryptPayload(key, hdr.AAD(), plaintext)
	if err != nil {
		return err
	}
	pkt := protocol.UDPPacket{Header: hdr, Payload: enc}
	wire, err := pkt.Marshal()
	if err != nil {
		return err
	}
	if rate := math.Float64frombits(e.dropRate.Load()); rate > 0 && rand.Float64() < rate {
		return nil // simulated loss
	}
	_, err = e.conn.WriteToUDP(wire, dst)
	return err
}

func (e *RDTEndpoint) isClosed() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

func copyAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	c := *a
	c.IP = append(net.IP(nil), a.IP...)
	return &c
}

// ========================= Delivery queues =========================

// deliveryQueue keeps the receive loop from blocking on a slow app; the backlog shrinks rwnd instead.
type deliveryQueue struct {
	mu     sync.Mutex
	items  []DeliveredPacket
	notify chan struct{}
	out    chan DeliveredPacket
}

func newDeliveryQueue() *deliveryQueue {
	return &deliveryQueue{notify: make(chan struct{}, 1), out: make(chan DeliveredPacket)}
}

func (q *deliveryQueue) push(pkts ...DeliveredPacket) {
	q.mu.Lock()
	q.items = append(q.items, pkts...)
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *deliveryQueue) pop() (DeliveredPacket, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return DeliveredPacket{}, false
	}
	p := q.items[0]
	q.items[0] = DeliveredPacket{}
	q.items = q.items[1:]
	if len(q.items) == 0 {
		q.items = nil
	}
	return p, true
}

func (e *RDTEndpoint) runDeliverer(q *deliveryQueue) {
	defer e.wg.Done()
	defer close(q.out)
	for {
		pkt, ok := q.pop()
		if !ok {
			select {
			case <-q.notify:
				continue
			case <-e.done:
				return
			}
		}
		select {
		case q.out <- pkt:
			e.markConsumed(recvStreamKey{sender: pkt.Header.SenderID, stream: pkt.Header.StreamID})
		case <-e.done:
			return
		}
	}
}
