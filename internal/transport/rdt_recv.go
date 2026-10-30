package transport

import (
	"errors"
	"net"
	"time"

	"lancollab/internal/protocol"
)

// ========================= Receive path =========================

func (e *RDTEndpoint) readLoop() {
	defer e.wg.Done()
	buf := make([]byte, 64*1024) // larger than any valid datagram, so oversized ones are detected
	for {
		n, from, err := e.conn.ReadFromUDP(buf)
		if err != nil {
			if e.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient errors (e.g. WSAECONNRESET from an ICMP on Windows) must not stop the loop.
			time.Sleep(time.Millisecond)
			continue
		}
		e.handleDatagram(buf[:n], from)
	}
}

func (e *RDTEndpoint) handleDatagram(raw []byte, from *net.UDPAddr) {
	if len(raw) > protocol.MaxDatagramSize {
		e.badPackets.Add(1)
		return
	}
	pkt, err := protocol.UnmarshalUDPPacket(raw) // magic, version, length, CRC-16
	if err != nil {
		e.badPackets.Add(1)
		return
	}
	key, _, ok := e.keyResolver(pkt.Header.SenderID)
	if !ok {
		e.badPackets.Add(1)
		return
	}
	plaintext, err := protocol.DecryptPayload(key, pkt.Header.AAD(), pkt.Payload)
	if err != nil {
		e.badPackets.Add(1)
		return
	}
	src := copyAddr(from)

	e.hookMu.RLock()
	hook := e.hook
	e.hookMu.RUnlock()
	if hook != nil {
		hook(pkt, plaintext, src)
	}

	h := pkt.Header
	switch {
	case h.MsgType == protocol.MsgPacketAck:
		e.handleAck(h, src)
	case protocol.IsDataMsg(h.MsgType):
		e.handleData(h, plaintext, key, src)
	}
}

// handleData runs the Selective Repeat receiver for one data packet.
func (e *RDTEndpoint) handleData(h protocol.UDPHeader, plaintext, key []byte, from *net.UDPAddr) {
	if h.StreamID == protocol.StreamHeartbeat {
		return
	}
	rk := recvStreamKey{sender: h.SenderID, stream: h.StreamID}
	var ready []DeliveredPacket
	sendAck := false

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	rs := e.recvStreams[rk]
	if rs == nil {
		rs = &recvStream{base: protocol.InitialSeq(h.StreamID), buf: make(map[uint32]DeliveredPacket)}
		e.recvStreams[rk] = rs
	}
	rs.lastActive = time.Now()
	seq := h.SeqNum
	switch {
	case seq < rs.base:
		// Already delivered: our earlier ACK was lost, so ACK again (Kurose §3.4.4).
		sendAck = true
	case seq >= rs.base+protocol.RecvWindow:
		// Beyond the receive window: drop without ACK; the sender will retransmit.
	default:
		if _, dup := rs.buf[seq]; dup {
			sendAck = true
		} else if len(rs.buf)+rs.pending < protocol.RecvWindow {
			rs.buf[seq] = DeliveredPacket{Header: h, Plaintext: plaintext, FromAddr: from}
			sendAck = true
			// Slide rcv_base over every consecutive packet we now hold.
			for {
				p, ok := rs.buf[rs.base]
				if !ok {
					break
				}
				delete(rs.buf, rs.base)
				ready = append(ready, p)
				rs.pending++
				rs.base++
			}
		}
		// Receive buffer full (app not reading): drop without ACK; the sender keeps one probe in flight.
	}
	rwnd := freeSlots(rs)
	e.mu.Unlock()

	if len(ready) > 0 {
		if h.StreamID == protocol.StreamChat {
			e.chatQ.push(ready...)
		} else {
			e.fileQ.push(ready...)
		}
	}
	if sendAck {
		ack := protocol.UDPHeader{
			MsgType:  protocol.MsgPacketAck,
			Flags:    protocol.FlagACK,
			Rwnd:     rwnd,
			StreamID: h.StreamID,
			SenderID: uint16(e.localID.Load()),
			TargetID: h.SenderID, // the original sender of the acknowledged packet
			AckNum:   h.SeqNum,
		}
		_ = e.transmit(from, key, ack, nil)
	}
}

// handleAck processes one individual ACK, then sends what fast retransmit selected.
func (e *RDTEndpoint) handleAck(h protocol.UDPHeader, from *net.UDPAddr) {
	e.sendResends(e.processAck(h, from))
}

// processAck updates sender state for one ACK; an older packet passed by 3 later ACKs is resent at once.
func (e *RDTEndpoint) processAck(h protocol.UDPHeader, from *net.UDPAddr) []resend {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	pk := pktKey{peer: h.SenderID, sender: h.TargetID, stream: h.StreamID, seq: h.AckNum}
	sp, ok := e.unacked[pk]
	if !ok && from != nil {
		// The ACK's sender_id did not match: fall back to finding the peer by source address.
		if id, found := e.peerByAddr[from.String()]; found && id != pk.peer {
			pk.peer = id
			sp, ok = e.unacked[pk]
		}
	}
	peer := e.peers[pk.peer]
	if peer != nil {
		peer.lastRwnd = h.Rwnd
	}
	sk := sendStreamKey{peer: pk.peer, sender: pk.sender, stream: pk.stream}
	ss := e.sendStreams[sk]
	if ss != nil {
		ss.rwnd = h.Rwnd
		ss.lastActive = now
	}
	if !ok {
		// Duplicate ACK for a packet already acknowledged: only the window update counts.
		e.cond.Broadcast()
		return nil
	}

	delete(e.unacked, pk)
	if peer != nil {
		peer.inFlight--
		peer.acked++
		peer.rtt.Update(now.Sub(sp.firstSent), sp.retransmitted) // Karn's rule inside
		peer.cc.OnAck()
	}
	if ss != nil {
		ss.inFlight--
		if pk.seq >= ss.base {
			ss.acked[pk.seq] = true
		}
		for ss.acked[ss.base] { // slide send_base past every acknowledged packet
			delete(ss.acked, ss.base)
			ss.base++
		}
	}

	var out []resend
	for k, other := range e.unacked {
		if k.peer != pk.peer || k.sender != pk.sender || k.stream != pk.stream || k.seq >= pk.seq {
			continue
		}
		other.laterAcks++
		if other.laterAcks < fastRetransmitThreshold || other.fastRetx {
			continue
		}
		other.fastRetx = true
		other.retransmitted = true
		other.hdr.Flags |= protocol.FlagRetrans
		other.lastSent = now
		if peer != nil {
			peer.retrans++
		}
		out = append(out, resend{peer: k.peer, dst: other.dst, key: other.key, hdr: other.hdr, plaintext: other.plaintext})
	}
	if len(out) > 0 && peer != nil && now.Sub(peer.lastLossReaction) >= peer.rtt.RTO() {
		peer.cc.OnLoss()
		peer.lastLossReaction = now
	}
	e.cond.Broadcast()
	return out
}

// sendResends transmits packets chosen for retransmission; call without e.mu held.
func (e *RDTEndpoint) sendResends(out []resend) {
	for _, r := range out {
		dst := r.dst
		if _, addr, ok := e.keyResolver(r.peer); ok && addr != nil {
			dst = addr // the peer may have moved (heartbeat from a new address)
		}
		_ = e.transmit(dst, r.key, r.hdr, r.plaintext)
	}
}

func (e *RDTEndpoint) markConsumed(k recvStreamKey) {
	e.mu.Lock()
	if rs := e.recvStreams[k]; rs != nil && rs.pending > 0 {
		rs.pending--
	}
	e.mu.Unlock()
}

func freeSlots(rs *recvStream) uint8 {
	free := protocol.RecvWindow - len(rs.buf) - rs.pending
	if free < 0 {
		free = 0
	}
	return uint8(free)
}

// ========================= Timers =========================

type resend struct {
	peer      uint16
	dst       *net.UDPAddr
	key       []byte
	hdr       protocol.UDPHeader
	plaintext []byte
}

func (e *RDTEndpoint) timerLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(retransmitTick)
	defer ticker.Stop()
	lastGC := time.Now()
	for {
		select {
		case <-e.done:
			return
		case now := <-ticker.C:
			e.retransmitExpired(now)
			if now.Sub(lastGC) >= gcInterval {
				e.collectIdle(now)
				lastGC = now
			}
		}
	}
}

// retransmitExpired resends timed-out packets; cwnd and RTO react at most once per RTO per peer.
func (e *RDTEndpoint) retransmitExpired(now time.Time) {
	var out []resend
	var lossPeers map[uint16]*peerState

	e.mu.Lock()
	for _, sp := range e.unacked {
		peer := e.peers[sp.id.peer]
		if peer == nil || now.Sub(sp.lastSent) < peer.rtt.RTO() {
			continue
		}
		sp.retransmitted = true
		sp.hdr.Flags |= protocol.FlagRetrans
		sp.lastSent = now
		peer.retrans++
		if lossPeers == nil {
			lossPeers = make(map[uint16]*peerState)
		}
		lossPeers[peer.id] = peer
		out = append(out, resend{peer: peer.id, dst: sp.dst, key: sp.key, hdr: sp.hdr, plaintext: sp.plaintext})
	}
	for _, peer := range lossPeers {
		if now.Sub(peer.lastLossReaction) >= peer.rtt.RTO() {
			peer.cc.OnLoss()
			peer.rtt.OnTimeout()
			peer.lastLossReaction = now
		}
	}
	e.mu.Unlock()

	e.sendResends(out)
}

// collectIdle forgets file streams idle for a minute; chat streams live as long as the peer.
func (e *RDTEndpoint) collectIdle(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, rs := range e.recvStreams {
		if k.stream >= protocol.FirstFileStream && len(rs.buf) == 0 && rs.pending == 0 && now.Sub(rs.lastActive) > streamIdleTimeout {
			delete(e.recvStreams, k)
		}
	}
	for k, ss := range e.sendStreams {
		if k.stream >= protocol.FirstFileStream && ss.inFlight == 0 && now.Sub(ss.lastActive) > streamIdleTimeout {
			delete(e.sendStreams, k)
		}
	}
	e.cond.Broadcast() // periodic safety wake-up for blocked senders
}
