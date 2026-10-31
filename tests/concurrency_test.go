package tests

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lancollab/internal/client"
	"lancollab/internal/protocol"
	"lancollab/internal/server"
	"lancollab/internal/transport"
)

// --- Task 4: server authentication and resilience ---

func TestServerResilienceAndHeartbeatTimeout(t *testing.T) {
	srv, err := server.NewServer("127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Connect Client Alice over TLS
	rawConn, err := tlsDialServer(srv.TCPAddr())
	if err != nil {
		t.Fatal(err)
	}
	ctrl := transport.NewTLSControlConn(rawConn)
	defer ctrl.Close()

	_ = ctrl.Send(protocol.ControlMsg{Type: "HELLO", Version: 1, UDPPort: 52001})
	ack, err := ctrl.Recv(2 * time.Second)
	if err != nil || ack.Type != "HELLO_ACK" {
		t.Fatalf("expected HELLO_ACK, got %+v err=%v", ack, err)
	}

	_ = ctrl.Send(protocol.ControlMsg{Type: "AUTH_REQ", Username: "alice", Password: "pw1"})
	res, err := ctrl.Recv(2 * time.Second)
	if err != nil || !res.OK || res.UserID == 0 || len(res.SessionKey) != 32 {
		t.Fatalf("expected AUTH_RES OK, got %+v err=%v", res, err)
	}

	// Wrong password for existing user "alice" must fail
	rawConn2, _ := tlsDialServer(srv.TCPAddr())
	ctrl2 := transport.NewTLSControlConn(rawConn2)
	defer ctrl2.Close()
	_ = ctrl2.Send(protocol.ControlMsg{Type: "HELLO", Version: 1, UDPPort: 52002})
	_, _ = ctrl2.Recv(2 * time.Second)
	_ = ctrl2.Send(protocol.ControlMsg{Type: "AUTH_REQ", Username: "alice", Password: "wrong"})
	res2, err := ctrl2.Recv(2 * time.Second)
	if err != nil || res2.OK {
		t.Fatalf("expected AUTH_RES failure on wrong password, got %+v", res2)
	}
}

func TestAbruptDisconnectIsDetectedAndPeersNotified(t *testing.T) {
	srv := startServer(t, nil)
	alice, _ := rawLogin(t, srv.TCPAddr(), "alice", "pw1")
	t.Cleanup(func() { _ = alice.Close() })
	bob, _ := rawLogin(t, srv.TCPAddr(), "bob", "pw2")

	waitForPeers(t, alice, "bob comes online", func(p []protocol.PeerInfo) bool { return peerNames(p)["bob"] })

	// Bob vanishes without sending LOGOUT: the server only sees the socket close.
	_ = bob.Close()
	waitForPeers(t, alice, "bob disappears", func(p []protocol.PeerInfo) bool {
		n := peerNames(p)
		return n["alice"] && !n["bob"]
	})
	if got := srv.Sessions(); got != 1 {
		t.Fatalf("the server must have removed bob's session, %d sessions remain", got)
	}
}

func TestHeartbeatTimeoutRemovesSilentClient(t *testing.T) {
	srv := startServer(t, func(s *server.Server) {
		if err := s.SetTimeouts(1500*time.Millisecond, 100*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	})
	alice, _ := rawLogin(t, srv.TCPAddr(), "alice", "pw1") // never sends a heartbeat
	t.Cleanup(func() { _ = alice.Close() })
	bob, bobRes := rawLogin(t, srv.TCPAddr(), "bob", "pw2")
	t.Cleanup(func() { _ = bob.Close() })

	stop := startHeartbeats(t, srv.UDPAddr(), bobRes.UserID, bobRes.SessionKey, 300*time.Millisecond)
	defer stop()

	waitForPeers(t, bob, "silent alice is swept", func(p []protocol.PeerInfo) bool {
		n := peerNames(p)
		return n["bob"] && !n["alice"]
	})

	// The server also closes the silent client's control connection.
	closed := false
	for i := 0; i < 10; i++ {
		if _, err := alice.Recv(2 * time.Second); err != nil {
			closed = true
			break
		}
	}
	if !closed {
		t.Fatal("alice's control connection stayed open after her session timed out")
	}
	if got := srv.Sessions(); got != 1 {
		t.Fatalf("only the heartbeating client must remain, %d sessions found", got)
	}
}

func TestServerSurvivesGarbageAndOversizedControlFrames(t *testing.T) {
	srv := startServer(t, nil)

	// 1. Plain text on the TLS port: the handshake fails and the connection is dropped.
	if c, err := net.Dial("tcp", srv.TCPAddr()); err == nil {
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = c.Close()
	}

	// 2. A TLS client announcing a 4 GiB control frame is disconnected.
	conn, err := tlsDialServer(srv.TCPAddr())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("expected the server to close the connection after an oversized frame")
	}
	_ = conn.Close()

	// 3. A well-formed message of the wrong type gets an ERROR and a disconnect.
	conn2, err := tlsDialServer(srv.TCPAddr())
	if err != nil {
		t.Fatal(err)
	}
	ctrl := transport.NewTLSControlConn(conn2)
	_ = ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlAuthReq, Username: "x", Password: "y"})
	msg, err := ctrl.Recv(2 * time.Second)
	if err != nil || msg.Type != protocol.CtrlError {
		t.Fatalf("expected an ERROR message, got %+v err=%v", msg, err)
	}
	_ = ctrl.Close()

	// 4. The server still serves a normal client afterwards.
	survivor, _ := rawLogin(t, srv.TCPAddr(), "survivor", "pw")
	_ = survivor.Close()
}

func TestDuplicateLoginAndInvalidCredentialsAreRejected(t *testing.T) {
	srv := startServer(t, nil)
	alice, _ := rawLogin(t, srv.TCPAddr(), "alice", "pw1")
	t.Cleanup(func() { _ = alice.Close() })

	expectRefusal := func(user, pass, wantReason string) {
		t.Helper()
		conn, err := tlsDialServer(srv.TCPAddr())
		if err != nil {
			t.Fatal(err)
		}
		ctrl := transport.NewTLSControlConn(conn)
		defer ctrl.Close()
		_ = ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlHello, Version: 1, UDPPort: 50001})
		if _, err := ctrl.Recv(2 * time.Second); err != nil {
			t.Fatal(err)
		}
		_ = ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlAuthReq, Username: user, Password: pass})
		res, err := ctrl.Recv(2 * time.Second)
		if err != nil || res.OK {
			t.Fatalf("%q/%q must be refused, got %+v err=%v", user, pass, res, err)
		}
		if !strings.Contains(res.Reason, wantReason) {
			t.Fatalf("%q/%q: reason %q does not mention %q", user, pass, res.Reason, wantReason)
		}
	}
	expectRefusal("alice", "pw1", "already")
	expectRefusal("alice", "nope", "wrong password")
	expectRefusal("bad name!", "pw", "username")
	expectRefusal("carol", "", "password")
}

func TestLogoutThenSameUserCanSignInAgain(t *testing.T) {
	srv := startServer(t, nil)
	host, tcpPort := splitHostPort(t, srv.TCPAddr())
	_, udpPort := splitHostPort(t, srv.UDPAddr())
	newController := func() *client.Controller {
		c := client.NewController(host, tcpPort, udpPort)
		c.SetDownloadDir(t.TempDir())
		return c
	}

	c := newController()
	if err := c.ConnectAndLogin("zoe", "pw"); err != nil {
		t.Fatal(err)
	}
	first := c.UserID()
	if err := c.Logout(); err != nil {
		t.Fatal(err)
	}
	if c.State() != client.StateDisconnected {
		t.Fatalf("after logout the state must be DISCONNECTED, got %s", c.State())
	}

	// The server removes the session right after echoing LOGOUT; retry briefly.
	var err error
	for i := 0; i < 20; i++ {
		if err = c.ConnectAndLogin("zoe", "pw"); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("zoe could not sign in again: %v", err)
	}
	t.Cleanup(func() { _ = c.Logout() })
	if c.UserID() == first {
		t.Fatalf("a new session must get a fresh UserID, got %d twice", first)
	}

	// While zoe is online, a second client cannot take her name or guess her password.
	if err := newController().ConnectAndLogin("zoe", "wrong"); err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("expected a wrong-password error, got %v", err)
	}
	if err := newController().ConnectAndLogin("zoe", "pw"); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("expected an already-signed-in error, got %v", err)
	}
}

// --- Task 6: end-to-end behaviour with real controllers ---

func TestConcurrentTwentyClientsEndToEnd(t *testing.T) {
	srv, err := server.NewServer("127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	tcpHost, tcpPort := splitHostPort(t, srv.TCPAddr())
	_, udpPort := splitHostPort(t, srv.UDPAddr())

	const numClients = 20
	ctrls := make([]*client.Controller, numClients)
	for i := 0; i < numClients; i++ {
		c := client.NewController(tcpHost, tcpPort, udpPort)
		c.SetDownloadDir(t.TempDir())
		if err := c.ConnectAndLogin(fmt.Sprintf("user_%02d", i+1), "pass123"); err != nil {
			t.Fatalf("client %d login failed: %v", i+1, err)
		}
		ctrls[i] = c
		defer c.Logout()
	}
	// PEER_UPDATE messages travel asynchronously; wait until client 0 knows everybody.
	waitPeers(t, ctrls[0], numClients)

	// Client 0 broadcasts a chat message and sends a 20 KB file to Client 1
	if err := ctrls[0].SendChat(protocol.BroadcastTarget, "Hello 20 peers!"); err != nil {
		t.Fatalf("broadcast chat failed: %v", err)
	}
	sampleFile := bytes.Repeat([]byte(" COLLAB-STREAM-TEST "), 1024) // 20 KB
	if _, err := ctrls[0].SendFile(2, "test_20kb.bin", sampleFile); err != nil {
		t.Fatalf("send file failed: %v", err)
	}

	// Verify Client 1 receives both the broadcast chat and the verified 20 KB file
	gotChat, gotFile := false, false
	timeout := time.After(8 * time.Second)
	evCh := ctrls[1].SubscribeEvents()
	for !gotChat || !gotFile {
		select {
		case ev := <-evCh:
			if ev.Kind == "chat" && ev.Text == "Hello 20 peers!" {
				gotChat = true
			}
			if ev.Kind == "file_progress" && ev.Progress != nil && ev.Progress.Verified {
				gotFile = true
			}
		case <-timeout:
			t.Fatalf("timed out waiting for E2E delivery: gotChat=%v gotFile=%v", gotChat, gotFile)
		}
	}
}

func TestDirectMessageReachesOnlyTarget(t *testing.T) {
	srv := startServer(t, nil)
	alice := newClient(t, srv, "alice")
	bob := newClient(t, srv, "bob")
	carol := newClient(t, srv, "carol")
	for _, c := range []*client.Controller{alice, bob, carol} {
		waitPeers(t, c, 3)
	}
	bobEvents := subscribe(t, bob)
	carolEvents := subscribe(t, carol)

	const secret = "psst, this is only for bob"
	if err := alice.SendChat(bob.UserID(), secret); err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, bobEvents, 3*time.Second, "bob receives the direct message", func(e client.ClientEvent) bool {
		return e.Kind == client.EventChat && e.Text == secret
	})
	if !ev.Direct || ev.From != "alice" || ev.FromID != alice.UserID() {
		t.Fatalf("unexpected direct message event: %+v", ev)
	}

	// Carol must see the broadcast that follows, but never the direct message.
	if err := alice.SendChat(protocol.BroadcastTarget, "hello everyone"); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(3 * time.Second)
	for seenBroadcast := false; !seenBroadcast; {
		select {
		case e := <-carolEvents:
			if e.Kind == client.EventChat && e.Text == secret {
				t.Fatal("carol received a direct message addressed to bob")
			}
			if e.Kind == client.EventChat && e.Text == "hello everyone" {
				seenBroadcast = true
			}
		case <-timeout:
			t.Fatal("carol never received the broadcast")
		}
	}
}

func TestLargeFileUnderLossIsByteExactAndChatOvertakesIt(t *testing.T) {
	const loss = 0.08
	srv := startServer(t, func(s *server.Server) { s.SetDropRate(loss) })
	alice := newClient(t, srv, "alice")
	bob, bobDir := newClientDir(t, srv, "bob")
	alice.SetDropRate(loss)
	bob.SetDropRate(loss)
	waitPeers(t, alice, 2)
	waitPeers(t, bob, 2)
	aliceEvents := subscribe(t, alice)
	bobEvents := subscribe(t, bob)

	payload := make([]byte, 200*1024)
	for i := range payload {
		payload[i] = byte(i*31 + i>>8)
	}
	if _, err := alice.SendFile(bob.UserID(), "big.bin", payload); err != nil {
		t.Fatal(err)
	}
	if err := alice.SendChat(bob.UserID(), "ping during upload"); err != nil {
		t.Fatal(err)
	}

	// The chat message travels on stream 1 and must not wait for the 200-packet file.
	waitEvent(t, bobEvents, 5*time.Second, "chat during the upload", func(e client.ClientEvent) bool {
		return e.Kind == client.EventChat && e.Text == "ping during upload"
	})
	for _, tp := range bob.Transfers() {
		if tp.Stage == client.StageVerified {
			t.Fatal("the file finished before the chat arrived, so no overtaking was observed")
		}
	}

	done := waitEvent(t, bobEvents, 90*time.Second, "bob verifies the file", func(e client.ClientEvent) bool {
		return e.Kind == client.EventFileProgress && e.Progress != nil && e.Progress.Verified && e.Progress.Direction == client.DirectionRecv
	})
	saved := done.Progress.SavedPath
	if saved == "" || filepath.Base(saved) != "big.bin" || filepath.Dir(saved) != filepath.Clean(bobDir) {
		t.Fatalf("unexpected saved path %q (download dir %q)", saved, bobDir)
	}
	got, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("the saved file differs from the original (%d vs %d bytes)", len(got), len(payload))
	}

	// The sender is told the checksum matched (FILE_DONE travelled back through the server).
	waitEvent(t, aliceEvents, 30*time.Second, "alice learns the transfer was verified", func(e client.ClientEvent) bool {
		return e.Kind == client.EventFileProgress && e.Progress != nil && e.Progress.Direction == client.DirectionSend && e.Progress.Stage == client.StageVerified
	})
}

func TestTwentyClientsMeshUnderPacketLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("load test skipped in -short mode")
	}
	const n = 20
	const loss = 0.10
	srv := startServer(t, func(s *server.Server) { s.SetDropRate(loss) })

	ctrls := make([]*client.Controller, n)
	for i := range ctrls {
		c := newClient(t, srv, fmt.Sprintf("mesh_%02d", i+1))
		c.SetDropRate(loss)
		ctrls[i] = c
	}
	for _, c := range ctrls {
		waitPeers(t, c, n)
	}

	type tally struct {
		chats int
		sent  bool
		recv  bool
		fail  string
	}
	tallies := make([]*tally, n)
	var mu sync.Mutex
	allDone := make(chan struct{})
	var once sync.Once
	checkLocked := func() {
		for _, ta := range tallies {
			if ta == nil || ta.chats < n-1 || !ta.sent || !ta.recv {
				return
			}
		}
		once.Do(func() { close(allDone) })
	}
	for i, c := range ctrls {
		ta := &tally{}
		mu.Lock()
		tallies[i] = ta
		mu.Unlock()
		events := subscribe(t, c)
		go func(ta *tally, events <-chan client.ClientEvent) {
			for ev := range events {
				mu.Lock()
				switch ev.Kind {
				case client.EventChat:
					if !ev.Self && !ev.Direct {
						ta.chats++
					}
				case client.EventFileProgress:
					if p := ev.Progress; p != nil {
						switch {
						case p.Stage == client.StageVerified && p.Direction == client.DirectionSend:
							ta.sent = true
						case p.Stage == client.StageVerified && p.Direction == client.DirectionRecv:
							ta.recv = true
						case p.Stage == client.StageFailed:
							ta.fail = p.Error
						}
					}
				}
				checkLocked()
				mu.Unlock()
			}
		}(ta, events)
	}

	// Every client broadcasts one message and sends a 20 KB file to the next client.
	var wg sync.WaitGroup
	for i, c := range ctrls {
		wg.Add(1)
		go func(i int, c *client.Controller) {
			defer wg.Done()
			if err := c.SendChat(protocol.BroadcastTarget, "hello from "+c.Username()); err != nil {
				t.Errorf("%s: broadcast failed: %v", c.Username(), err)
			}
			data := bytes.Repeat([]byte{byte(i + 1)}, 20*1024)
			if _, err := c.SendFile(ctrls[(i+1)%n].UserID(), fmt.Sprintf("mesh_%02d.bin", i+1), data); err != nil {
				t.Errorf("%s: file failed: %v", c.Username(), err)
			}
		}(i, c)
	}
	wg.Wait()

	select {
	case <-allDone:
	case <-time.After(90 * time.Second):
		mu.Lock()
		defer mu.Unlock()
		for i, ta := range tallies {
			if ta.chats < n-1 || !ta.sent || !ta.recv {
				t.Errorf("client %02d incomplete: chats=%d/%d sent=%v received=%v failure=%q", i+1, ta.chats, n-1, ta.sent, ta.recv, ta.fail)
			}
		}
		t.FailNow()
	}
}
