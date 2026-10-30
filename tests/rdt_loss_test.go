package tests

import (
	"bytes"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"lancollab/internal/protocol"
	"lancollab/internal/transport"
)

// --- Task 2: RTT estimator and CUBIC ---

func TestRTTEstimatorAndKarnsRule(t *testing.T) {
	rtt := transport.NewRTTEstimator()
	initRTO := rtt.RTO()

	// Retransmitted sample must be ignored (Karn's rule)
	rtt.Update(500*time.Millisecond, true)
	if rtt.RTO() != initRTO {
		t.Fatalf("Karn's rule violated: RTO changed from %v to %v", initRTO, rtt.RTO())
	}

	// Valid sample updates RTO; consecutive timeout doubles RTO
	rtt.Update(60*time.Millisecond, false)
	beforeBackoff := rtt.RTO()
	rtt.OnTimeout()
	if rtt.RTO() < beforeBackoff*2 {
		t.Fatalf("expected RTO to double on timeout, got %v -> %v", beforeBackoff, rtt.RTO())
	}
}

func TestRTTEstimatorClampsAndRecovers(t *testing.T) {
	rtt := transport.NewRTTEstimator()
	if rtt.RTO() != protocol.InitialRTO {
		t.Fatalf("initial RTO must be 200 ms, got %v", rtt.RTO())
	}
	for i := 0; i < 100; i++ {
		rtt.Update(time.Millisecond, false)
	}
	if rtt.RTO() != protocol.MinRTO {
		t.Fatalf("a 1 ms LAN must clamp RTO to the 50 ms floor, got %v", rtt.RTO())
	}
	for i := 0; i < 20; i++ {
		rtt.OnTimeout()
	}
	if rtt.RTO() != protocol.MaxRTO {
		t.Fatalf("repeated timeouts must back off to the 2000 ms ceiling, got %v", rtt.RTO())
	}
	rtt.Update(time.Millisecond, false)
	if rtt.RTO() != protocol.MinRTO {
		t.Fatalf("a fresh sample must cancel the backoff, got %v", rtt.RTO())
	}
}

func TestCubicCongestionAndFlowControlWindow(t *testing.T) {
	cc := transport.NewCubicController()
	if w := cc.EffectiveWindow(64); w != 4 {
		t.Fatalf("expected initial cwnd 4, got %d", w)
	}
	for i := 0; i < 6; i++ {
		cc.OnAck()
	}
	if w := cc.EffectiveWindow(64); w <= 4 {
		t.Fatalf("expected cwnd to grow on ACKs, got %d", w)
	}
	// Flow control rwnd=3 must cap effective window at 3
	if w := cc.EffectiveWindow(3); w != 3 {
		t.Fatalf("expected rwnd=3 to cap window, got %d", w)
	}
	beforeLoss := cc.EffectiveWindow(64)
	cc.OnLoss()
	if after := cc.EffectiveWindow(64); after >= beforeLoss {
		t.Fatalf("expected cwnd reduction on loss: %d -> %d", beforeLoss, after)
	}
}

func TestCubicStaysBoundedAndNeverStalls(t *testing.T) {
	cc := transport.NewCubicController()
	if w := cc.EffectiveWindow(0); w != 1 {
		t.Fatalf("a zero receive window must still allow one probe packet, got %d", w)
	}
	for i := 0; i < 5000; i++ {
		cc.OnAck()
	}
	if w := cc.Cwnd(); w < protocol.InitialSsthresh || w > protocol.MaxCwnd {
		t.Fatalf("cwnd must stay within [ssthresh, 64] after many ACKs, got %v", w)
	}
	cc.OnLoss()
	if s := cc.Ssthresh(); s < 2 {
		t.Fatalf("ssthresh must never drop below 2, got %v", s)
	}
	for i := 0; i < 100; i++ {
		cc.OnLoss()
	}
	if w := cc.Cwnd(); w < 2 {
		t.Fatalf("cwnd must never drop below 2, got %v", w)
	}
}

// --- Helpers for the transport tests ---

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// endpointPair is two RDT endpoints talking directly (a = node 1, b = node 2).
type endpointPair struct {
	a, b         *transport.RDTEndpoint
	addrA, addrB *net.UDPAddr
	key          []byte
}

func newPair(t *testing.T) *endpointPair {
	t.Helper()
	key, err := protocol.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := listenLoopback(t), listenLoopback(t)
	p := &endpointPair{
		addrA: c1.LocalAddr().(*net.UDPAddr),
		addrB: c2.LocalAddr().(*net.UDPAddr),
		key:   key,
	}
	p.a = transport.NewRDTEndpoint(c1, func(uint16) ([]byte, *net.UDPAddr, bool) { return key, p.addrB, true })
	p.b = transport.NewRDTEndpoint(c2, func(uint16) ([]byte, *net.UDPAddr, bool) { return key, p.addrA, true })
	t.Cleanup(func() { _ = p.a.Close(); _ = p.b.Close() })
	return p
}

// lossyProxy forwards between A and B and drops the first N copies of chosen packets (headers are plaintext).
type lossyProxy struct {
	conn  *net.UDPConn
	addrA *net.UDPAddr
	addrB *net.UDPAddr

	mu       sync.Mutex
	copies   map[[2]uint32]int
	dropLeft map[[2]uint32]int
	wg       sync.WaitGroup
}

func newLossyProxy(t *testing.T, addrA, addrB *net.UDPAddr, drop map[[2]uint32]int) *lossyProxy {
	t.Helper()
	p := &lossyProxy{
		conn:     listenLoopback(t),
		addrA:    addrA,
		addrB:    addrB,
		copies:   make(map[[2]uint32]int),
		dropLeft: make(map[[2]uint32]int),
	}
	for k, v := range drop {
		p.dropLeft[k] = v
	}
	p.wg.Add(1)
	go p.loop()
	t.Cleanup(func() { _ = p.conn.Close(); p.wg.Wait() })
	return p
}

func (p *lossyProxy) addr() *net.UDPAddr { return p.conn.LocalAddr().(*net.UDPAddr) }

func (p *lossyProxy) seen(stream uint16, seq uint32) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.copies[[2]uint32{uint32(stream), seq}]
}

func (p *lossyProxy) loop() {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, from, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := append([]byte(nil), buf[:n]...)
		if from.String() != p.addrA.String() {
			_, _ = p.conn.WriteToUDP(data, p.addrA) // B -> A: always forwarded
			continue
		}
		if pkt, err := protocol.UnmarshalUDPPacket(data); err == nil && protocol.IsDataMsg(pkt.Header.MsgType) {
			k := [2]uint32{uint32(pkt.Header.StreamID), pkt.Header.SeqNum}
			p.mu.Lock()
			p.copies[k]++
			drop := p.dropLeft[k] > 0
			if drop {
				p.dropLeft[k]--
			}
			p.mu.Unlock()
			if drop {
				continue
			}
		}
		_, _ = p.conn.WriteToUDP(data, p.addrB)
	}
}

type proxiedPair struct {
	a, b  *transport.RDTEndpoint
	proxy *lossyProxy
	key   []byte
}

func newProxiedPair(t *testing.T, drop map[[2]uint32]int) *proxiedPair {
	t.Helper()
	key, err := protocol.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := listenLoopback(t), listenLoopback(t)
	px := newLossyProxy(t, c1.LocalAddr().(*net.UDPAddr), c2.LocalAddr().(*net.UDPAddr), drop)
	resolve := func(uint16) ([]byte, *net.UDPAddr, bool) { return key, px.addr(), true }
	out := &proxiedPair{
		a:     transport.NewRDTEndpoint(c1, resolve),
		b:     transport.NewRDTEndpoint(c2, resolve),
		proxy: px,
		key:   key,
	}
	t.Cleanup(func() { _ = out.a.Close(); _ = out.b.Close() })
	return out
}

// --- Task 3: Selective Repeat and head-of-line freedom ---

func TestRDTSelectiveRepeatAndHoLFree(t *testing.T) {
	key, _ := protocol.GenerateSessionKey()
	c1, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	c2, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer c1.Close()
	defer c2.Close()

	addr1 := c1.LocalAddr().(*net.UDPAddr)
	addr2 := c2.LocalAddr().(*net.UDPAddr)

	epA := transport.NewRDTEndpoint(c1, func(id uint16) ([]byte, *net.UDPAddr, bool) {
		return key, addr2, true
	})
	epB := transport.NewRDTEndpoint(c2, func(id uint16) ([]byte, *net.UDPAddr, bool) {
		return key, addr1, true
	})
	defer epA.Close()
	defer epB.Close()

	// Inject 15% random packet loss on sender
	epA.SetDropRate(0.15)

	// Send 40 file chunks on Stream 2 AND 5 chat messages on Stream 1 concurrently
	rawFile := bytes.Repeat([]byte("FILE-DATA-BLOCK-"), 2560) // 40 KB = 40 chunks
	meta, chunks := protocol.SplitFileChunks(rawFile)

	go func() {
		initBytes, _ := json.Marshal(meta)
		_ = epA.SendReliable(2, addr2, key, protocol.UDPHeader{
			MsgType: protocol.MsgFileInit, StreamID: 2, SenderID: 1, TargetID: 2, SeqNum: 0,
		}, initBytes)
		for i, ch := range chunks {
			_ = epA.SendReliable(2, addr2, key, protocol.UDPHeader{
				MsgType: protocol.MsgFileChunk, StreamID: 2, SenderID: 1, TargetID: 2, SeqNum: uint32(i + 1),
			}, ch)
		}
	}()

	go func() {
		for i := uint32(1); i <= 5; i++ {
			_ = epA.SendReliable(2, addr2, key, protocol.UDPHeader{
				MsgType: protocol.MsgChat, Flags: protocol.FlagEOM, StreamID: protocol.StreamChat, SenderID: 1, TargetID: 2, SeqNum: i,
			}, []byte("chat-msg"))
		}
	}()

	// Verify all 5 chat messages arrive and all 40 file chunks reassemble to exact SHA-256
	reasm := protocol.NewFileReassembler()
	chatsReceived := 0
	fileDone := false
	timeout := time.After(8 * time.Second)
	for chatsReceived < 5 || !fileDone {
		select {
		case <-epB.ChatChan():
			chatsReceived++
		case pkt := <-epB.FileChan():
			if pkt.Header.MsgType == protocol.MsgFileInit {
				var m protocol.FileInitMeta
				_ = json.Unmarshal(pkt.Plaintext, &m)
				reasm.AddInit(pkt.Header.SenderID, pkt.Header.StreamID, m)
			} else if pkt.Header.MsgType == protocol.MsgFileChunk {
				if out, _, done, err := reasm.AddChunk(pkt.Header.SenderID, pkt.Header.StreamID, pkt.Header.SeqNum, pkt.Plaintext); err == nil && done {
					if bytes.Equal(out, rawFile) {
						fileDone = true
					}
				}
			}
		case <-timeout:
			t.Fatalf("timed out waiting for RDT: chats=%d/5 fileDone=%v", chatsReceived, fileDone)
		}
	}
}

func TestRDTChatOvertakesStalledFileStream(t *testing.T) {
	// FILE_INIT's first two copies are lost; the chat message on stream 1 must still arrive at once (no HoL).
	px := newProxiedPair(t, map[[2]uint32]int{{2, 0}: 2})
	dst := px.proxy.addr()
	send := func(h protocol.UDPHeader, body string) {
		t.Helper()
		if err := px.a.SendReliable(2, dst, px.key, h, []byte(body)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	send(protocol.UDPHeader{MsgType: protocol.MsgFileInit, StreamID: 2, SenderID: 1, TargetID: 2, SeqNum: 0}, "init")
	send(protocol.UDPHeader{MsgType: protocol.MsgFileChunk, StreamID: 2, SenderID: 1, TargetID: 2, SeqNum: 1}, "c1")
	send(protocol.UDPHeader{MsgType: protocol.MsgFileChunk, StreamID: 2, SenderID: 1, TargetID: 2, SeqNum: 2}, "c2")
	send(protocol.UDPHeader{MsgType: protocol.MsgChat, Flags: protocol.FlagEOM, StreamID: protocol.StreamChat, SenderID: 1, TargetID: 2, SeqNum: 1}, "hello")

	select {
	case p := <-px.b.ChatChan():
		if string(p.Plaintext) != "hello" {
			t.Fatalf("unexpected chat payload %q", p.Plaintext)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the chat message was blocked by a lost file packet (head-of-line blocking)")
	}
	chatAt := time.Now()

	select {
	case p := <-px.b.FileChan():
		t.Fatalf("file packet %d was delivered although FILE_INIT is still missing", p.Header.SeqNum)
	default:
	}

	// The stalled stream recovers by retransmission and is then delivered in order.
	for want := uint32(0); want <= 2; want++ {
		select {
		case p := <-px.b.FileChan():
			if p.Header.SeqNum != want {
				t.Fatalf("stream 2 delivered seq %d, want %d", p.Header.SeqNum, want)
			}
			if want == 0 {
				if p.Header.Flags&protocol.FlagRetrans == 0 {
					t.Fatal("FILE_INIT must arrive as a retransmission")
				}
				if !time.Now().After(chatAt) {
					t.Fatal("FILE_INIT must be delivered after the chat message")
				}
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("stream 2 never recovered (waiting for seq %d)", want)
		}
	}
}

func TestRDTRetransmitsOnlyTheLostPacket(t *testing.T) {
	// Lose chunk 3 once: SR must resend only that packet, not the whole window like Go-Back-N.
	px := newProxiedPair(t, map[[2]uint32]int{{2, 3}: 1})
	const last = 12
	go func() {
		for seq := uint32(0); seq <= last; seq++ {
			typ := protocol.MsgFileChunk
			if seq == 0 {
				typ = protocol.MsgFileInit
			}
			err := px.a.SendReliable(2, px.proxy.addr(), px.key, protocol.UDPHeader{
				MsgType: typ, StreamID: 2, SenderID: 1, TargetID: 2, SeqNum: seq,
			}, []byte{byte(seq)})
			if err != nil {
				t.Errorf("send seq %d: %v", seq, err)
				return
			}
		}
	}()

	for want := uint32(0); want <= last; want++ {
		select {
		case p := <-px.b.FileChan():
			if p.Header.SeqNum != want {
				t.Fatalf("delivered seq %d, want %d", p.Header.SeqNum, want)
			}
			if want == 3 && p.Header.Flags&protocol.FlagRetrans == 0 {
				t.Error("the lost packet must arrive as a retransmission")
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for seq %d", want)
		}
	}

	if got := px.proxy.seen(2, 3); got != 2 {
		t.Fatalf("the lost packet should have been sent exactly twice, was sent %d times", got)
	}
	others := 0
	for seq := uint32(0); seq <= last; seq++ {
		if seq != 3 && px.proxy.seen(2, seq) > 1 {
			others++
		}
	}
	if others > 1 { // tolerate one spurious timeout on a heavily loaded machine
		t.Fatalf("Selective Repeat must resend only the lost packet, but %d other packets were resent", others)
	}
	if st := px.a.Stats(2); st.Retransmissions < 1 {
		t.Fatalf("the sender must count its retransmission, stats=%+v", st)
	}
}

func TestRDTDropsCorruptedAndForeignDatagramsAndSuppressesDuplicates(t *testing.T) {
	key, _ := protocol.GenerateSessionKey()
	otherKey, _ := protocol.GenerateSessionKey()
	c2 := listenLoopback(t)
	addr2 := c2.LocalAddr().(*net.UDPAddr)
	epB := transport.NewRDTEndpoint(c2, func(uint16) ([]byte, *net.UDPAddr, bool) { return key, nil, true })
	t.Cleanup(func() { _ = epB.Close() })

	raw := listenLoopback(t)
	t.Cleanup(func() { _ = raw.Close() })

	build := func(k []byte, seq uint32, mutate func([]byte)) []byte {
		hdr := protocol.UDPHeader{
			MsgType: protocol.MsgChat, Flags: protocol.FlagEOM, StreamID: protocol.StreamChat,
			SenderID: 1, TargetID: 2, SeqNum: seq,
		}
		enc, err := protocol.EncryptPayload(k, hdr.AAD(), []byte(`{"from":"a","text":"x"}`))
		if err != nil {
			t.Fatal(err)
		}
		pkt := &protocol.UDPPacket{Header: hdr, Payload: enc}
		wire, err := pkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(wire)
		}
		return wire
	}
	send := func(b []byte) {
		t.Helper()
		if _, err := raw.WriteToUDP(b, addr2); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Garbage, a flipped bit (CRC fails) and a wrong-key datagram (GCM fails) are dropped silently.
	send([]byte("this is not a LanCollab datagram, just some bytes"))
	send(build(key, 1, func(w []byte) { w[len(w)-1] ^= 0x01 }))
	send(build(otherKey, 1, nil))
	deadline := time.Now().Add(2 * time.Second)
	for epB.BadPackets() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := epB.BadPackets(); got < 3 {
		t.Fatalf("expected 3 rejected datagrams, counted %d", got)
	}
	select {
	case <-epB.ChatChan():
		t.Fatal("a corrupted or foreign datagram was delivered to the application")
	case <-time.After(150 * time.Millisecond):
	}

	// 2. The same datagram twice is delivered once and ACKed twice (in case the first ACK was lost).
	good := build(key, 1, nil)
	send(good)
	send(good)
	select {
	case <-epB.ChatChan():
	case <-time.After(2 * time.Second):
		t.Fatal("the valid datagram was not delivered")
	}
	select {
	case <-epB.ChatChan():
		t.Fatal("a duplicate datagram was delivered twice")
	case <-time.After(300 * time.Millisecond):
	}

	acks := 0
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	for acks < 2 {
		n, _, err := raw.ReadFromUDP(buf)
		if err != nil {
			break
		}
		pkt, err := protocol.UnmarshalUDPPacket(buf[:n])
		if err == nil && pkt.Header.MsgType == protocol.MsgPacketAck && pkt.Header.AckNum == 1 {
			acks++
		}
	}
	if acks != 2 {
		t.Fatalf("expected both copies to be acknowledged, got %d ACKs", acks)
	}
}

func TestRDTSlowConsumerBackPressureLosesNothing(t *testing.T) {
	// A slow reader fills the 64-slot buffer; packets that do not fit are dropped unACKed and resent, none lost.
	pair := newPair(t)
	const total = 150
	go func() {
		for seq := uint32(0); seq < total; seq++ {
			err := pair.a.SendReliable(2, pair.addrB, pair.key, protocol.UDPHeader{
				MsgType: protocol.MsgFileChunk, StreamID: 2, SenderID: 1, TargetID: 2, SeqNum: seq,
			}, []byte{byte(seq)})
			if err != nil {
				t.Errorf("send seq %d: %v", seq, err)
				return
			}
		}
	}()
	for want := uint32(0); want < total; want++ {
		select {
		case p := <-pair.b.FileChan():
			if p.Header.SeqNum != want || len(p.Plaintext) != 1 || p.Plaintext[0] != byte(want) {
				t.Fatalf("delivered seq %d (payload %v), want %d", p.Header.SeqNum, p.Plaintext, want)
			}
			time.Sleep(2 * time.Millisecond)
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for seq %d", want)
		}
	}
}

func TestRDTFastRetransmitKeepsLossyTransferFast(t *testing.T) {
	// 2 MB at 5% loss: fast retransmit repairs losses after 3 later ACKs instead of waiting for the RTO.
	if testing.Short() {
		t.Skip("timing test skipped in -short mode")
	}
	pair := newPair(t)
	pair.a.SetDropRate(0.05)
	const chunks = 2048
	payload := bytes.Repeat([]byte{0x5A}, protocol.MaxChunkSize)

	start := time.Now()
	go func() {
		for seq := uint32(0); seq <= chunks; seq++ {
			typ := protocol.MsgFileChunk
			body := payload
			if seq == 0 {
				typ, body = protocol.MsgFileInit, []byte("init")
			}
			err := pair.a.SendReliable(2, pair.addrB, pair.key, protocol.UDPHeader{
				MsgType: typ, StreamID: 2, SenderID: 1, TargetID: 2, SeqNum: seq,
			}, body)
			if err != nil {
				t.Errorf("send seq %d: %v", seq, err)
				return
			}
		}
	}()
	for want := uint32(0); want <= chunks; want++ {
		select {
		case p := <-pair.b.FileChan():
			if p.Header.SeqNum != want {
				t.Fatalf("delivered seq %d, want %d", p.Header.SeqNum, want)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("timed out waiting for seq %d", want)
		}
	}
	elapsed := time.Since(start)
	st := pair.a.Stats(2)
	t.Logf("2 MB at 5%% loss took %v (%d retransmissions)", elapsed.Round(time.Millisecond), st.Retransmissions)
	if raceEnabled {
		return // the race detector slows everything down several times; no timing bound
	}
	if elapsed > 3*time.Second {
		t.Fatalf("recovery is too slow: %v for 2 MB at 5%% loss", elapsed)
	}
}
