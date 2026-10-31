package tests

import (
	"net"
	"strings"
	"testing"
	"time"

	"lancollab/internal/client"
	"lancollab/internal/protocol"
	"lancollab/internal/server"
	"lancollab/internal/transport"
)

// transferOf returns the transfer with the given stream and direction, if c knows it.
func transferOf(c *client.Controller, stream uint16, dir string) (client.TransferProgress, bool) {
	for _, tp := range c.Transfers() {
		if tp.StreamID == stream && tp.Direction == dir {
			return tp, true
		}
	}
	return client.TransferProgress{}, false
}

// waitTransferStage polls until the transfer reaches want, or fails after d.
func waitTransferStage(t *testing.T, c *client.Controller, stream uint16, dir, want string, d time.Duration) client.TransferProgress {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		tp, ok := transferOf(c, stream, dir)
		if ok && tp.Stage == want {
			return tp
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: transfer %d (%s) is %q after %v, want %q", c.Username(), stream, dir, tp.Stage, d, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startStuckClient signs in a raw client that heartbeats but never ACKs data; it returns its ID and a disconnect func.
func startStuckClient(t *testing.T, srv *server.Server, name string) (uint16, func()) {
	t.Helper()
	conn, err := tlsDialServer(srv.TCPAddr())
	if err != nil {
		t.Fatal(err)
	}
	ctrl := transport.NewTLSControlConn(conn)
	udp := listenLoopback(t)
	t.Cleanup(func() { _ = ctrl.Close(); _ = udp.Close() })

	hello := protocol.ControlMsg{Type: protocol.CtrlHello, Version: 1, UDPPort: udp.LocalAddr().(*net.UDPAddr).Port}
	if err := ctrl.Send(hello); err != nil {
		t.Fatal(err)
	}
	if _, err := ctrl.Recv(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlAuthReq, Username: name, Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	res, err := ctrl.Recv(2 * time.Second)
	if err != nil || !res.OK {
		t.Fatalf("%s could not sign in: %+v %v", name, res, err)
	}
	go func() { // read and ignore PEER_UPDATE messages
		for {
			if _, err := ctrl.Recv(0); err != nil {
				return
			}
		}
	}()

	srvAddr, err := net.ResolveUDPAddr("udp", srv.UDPAddr())
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			hd := protocol.UDPHeader{MsgType: protocol.MsgHeartbeat, SenderID: res.UserID}
			enc, _ := protocol.EncryptPayload(res.SessionKey, hd.AAD(), nil)
			wire, _ := (&protocol.UDPPacket{Header: hd, Payload: enc}).Marshal()
			_, _ = udp.WriteToUDP(wire, srvAddr)
			select {
			case <-stop:
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
	}()
	return res.UserID, func() { _ = ctrl.Close() }
}

func TestSenderLeavesMidTransferFailsReceiverSide(t *testing.T) {
	srv := startServer(t, nil)
	alice := newClient(t, srv, "alice")
	bob := newClient(t, srv, "bob")
	waitPeers(t, alice, 2)
	waitPeers(t, bob, 2)

	alice.SetDropRate(0.05)
	stream, err := alice.SendFile(bob.UserID(), "big.bin", make([]byte, 8<<20))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if tp, ok := transferOf(bob, stream, client.DirectionRecv); ok && tp.Stage == client.StageReceiving && tp.Percent > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bob never started receiving")
		}
		time.Sleep(10 * time.Millisecond)
	}

	_ = alice.Logout() // the sender disappears halfway through the file

	tp := waitTransferStage(t, bob, stream, client.DirectionRecv, client.StageFailed, 3*time.Second)
	if !strings.Contains(tp.Error, "went offline") {
		t.Fatalf("the receiver should be told why the transfer failed, got %q", tp.Error)
	}
}

func TestPeerLeavingFailsTransferAwaitingConfirmation(t *testing.T) {
	// The recipient never confirms and then disconnects: the sender must not wait for FILE_DONE forever.
	srv := startServer(t, nil)
	sink, disconnect := startStuckClient(t, srv, "sink")
	alice := newClient(t, srv, "alice")
	waitPeers(t, alice, 2)

	stream, err := alice.SendFile(sink, "small.bin", make([]byte, 20<<10))
	if err != nil {
		t.Fatal(err)
	}
	waitTransferStage(t, alice, stream, client.DirectionSend, client.StageAwaitingConfirm, 5*time.Second)

	disconnect()

	tp := waitTransferStage(t, alice, stream, client.DirectionSend, client.StageFailed, 3*time.Second)
	if !strings.Contains(tp.Error, "sink went offline") {
		t.Fatalf("unexpected failure reason %q", tp.Error)
	}
}

func TestRelayOverflowFailsOnlyTheOverflowingTransfer(t *testing.T) {
	// With a 64-packet queue limit, a stuck recipient fails only its own transfer and the sender is told.
	srv := startServer(t, func(s *server.Server) {
		if err := s.SetFileQueueLimit(64); err != nil {
			t.Fatal(err)
		}
	})
	sink, _ := startStuckClient(t, srv, "sink")
	alice := newClient(t, srv, "alice")
	carol := newClient(t, srv, "carol")
	dave := newClient(t, srv, "dave")
	for _, c := range []*client.Controller{alice, carol, dave} {
		waitPeers(t, c, 4)
	}

	stream, err := alice.SendFile(sink, "toSink.bin", make([]byte, 1<<20)) // about 1,000 packets
	if err != nil {
		t.Fatal(err)
	}
	tp := waitTransferStage(t, alice, stream, client.DirectionSend, client.StageFailed, 5*time.Second)
	if !strings.Contains(tp.Error, "too slow") {
		t.Fatalf("the sender should learn that the recipient is too slow, got %q", tp.Error)
	}

	s2, err := carol.SendFile(dave.UserID(), "ok.bin", make([]byte, 50<<10))
	if err != nil {
		t.Fatal(err)
	}
	waitTransferStage(t, carol, s2, client.DirectionSend, client.StageVerified, 5*time.Second)
	waitTransferStage(t, dave, s2, client.DirectionRecv, client.StageVerified, 5*time.Second)
}

func TestReceiverLeavesMidTransferFailsSender(t *testing.T) {
	srv := startServer(t, nil)
	alice := newClient(t, srv, "alice")
	bob := newClient(t, srv, "bob")
	waitPeers(t, alice, 2)
	waitPeers(t, bob, 2)

	alice.SetDropRate(0.05)
	stream, err := alice.SendFile(bob.UserID(), "big.bin", make([]byte, 8<<20))
	if err != nil {
		t.Fatal(err)
	}
	waitTransferStage(t, bob, stream, client.DirectionRecv, client.StageReceiving, 5*time.Second)

	_ = bob.Logout() // the receiver disappears halfway through the file

	// Either the peer list or the server's FILE_DONE may report it first.
	tp := waitTransferStage(t, alice, stream, client.DirectionSend, client.StageFailed, 3*time.Second)
	if !strings.Contains(tp.Error, "offline") {
		t.Fatalf("the sender should be told why the transfer failed, got %q", tp.Error)
	}
}

func TestSlowRecipientDoesNotStallOthers(t *testing.T) {
	// A recipient that never ACKs must not delay files or chat between other users.
	srv := startServer(t, nil)
	sink, _ := startStuckClient(t, srv, "sink")
	alice := newClient(t, srv, "alice")
	carol := newClient(t, srv, "carol")
	dave := newClient(t, srv, "dave")
	for _, c := range []*client.Controller{alice, carol, dave} {
		waitPeers(t, c, 4)
	}

	if _, err := alice.SendFile(sink, "toSink.bin", make([]byte, 4<<20)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond) // let the sink's queue on the server fill up

	stream, err := carol.SendFile(dave.UserID(), "ok.bin", make([]byte, 50<<10))
	if err != nil {
		t.Fatal(err)
	}
	waitTransferStage(t, dave, stream, client.DirectionRecv, client.StageVerified, 5*time.Second)

	events := dave.SubscribeEvents()
	defer dave.UnsubscribeEvents(events)
	if err := carol.SendChat(dave.UserID(), "ping"); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(2 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Kind == client.EventChat && ev.Text == "ping" {
				return
			}
		case <-timeout:
			t.Fatal("chat between other users was blocked by the slow recipient")
		}
	}
}
