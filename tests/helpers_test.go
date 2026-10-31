package tests

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"lancollab/internal/protocol"
	"lancollab/internal/transport"
)

// tlsDialServer opens a TLS connection to the server's control plane.
func tlsDialServer(addr string) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, protocol.NewClientTLSConfig())
}

// splitHostPort splits "host:port" and fails the test on malformed input.
func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("bad address %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("bad port in %q: %v", addr, err)
	}
	return host, port
}

// rawLogin does HELLO / AUTH_REQ on a new connection and fails the test unless sign-in succeeds.
func rawLogin(t *testing.T, tcpAddr, user, pass string) (*transport.TLSControlConn, protocol.ControlMsg) {
	t.Helper()
	conn, err := tlsDialServer(tcpAddr)
	if err != nil {
		t.Fatalf("dial %s: %v", tcpAddr, err)
	}
	ctrl := transport.NewTLSControlConn(conn)
	if err := ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlHello, Version: 1, UDPPort: 50000}); err != nil {
		t.Fatalf("send HELLO: %v", err)
	}
	if ack, err := ctrl.Recv(2 * time.Second); err != nil || ack.Type != protocol.CtrlHelloAck {
		t.Fatalf("expected HELLO_ACK, got %+v err=%v", ack, err)
	}
	if err := ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlAuthReq, Username: user, Password: pass}); err != nil {
		t.Fatalf("send AUTH_REQ: %v", err)
	}
	res, err := ctrl.Recv(2 * time.Second)
	if err != nil || res.Type != protocol.CtrlAuthRes || !res.OK {
		t.Fatalf("expected successful AUTH_RES for %s, got %+v err=%v", user, res, err)
	}
	return ctrl, res
}

// waitForPeers reads control messages until a PEER_UPDATE satisfies pred.
func waitForPeers(t *testing.T, ctrl *transport.TLSControlConn, what string, pred func([]protocol.PeerInfo) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timed out waiting for PEER_UPDATE: %s", what)
		}
		msg, err := ctrl.Recv(remaining)
		if err != nil {
			t.Fatalf("waiting for PEER_UPDATE (%s): %v", what, err)
		}
		if msg.Type == protocol.CtrlPeerUpdate && pred(msg.Peers) {
			return
		}
	}
}

// startHeartbeats keeps a raw session alive with a HEARTBEAT every interval until stop is called.
func startHeartbeats(t *testing.T, udpAddr string, userID uint16, key []byte, interval time.Duration) func() {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	send := func() {
		hdr := protocol.UDPHeader{
			Magic:    protocol.Magic,
			Version:  protocol.Version,
			MsgType:  protocol.MsgHeartbeat,
			StreamID: protocol.StreamHeartbeat,
			SenderID: userID,
			TargetID: protocol.ServerID,
		}
		enc, err := protocol.EncryptPayload(key, hdr.AAD(), nil)
		if err != nil {
			return
		}
		pkt := &protocol.UDPPacket{Header: hdr, Payload: enc}
		wire, err := pkt.Marshal()
		if err != nil {
			return
		}
		_, _ = conn.Write(wire)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		send()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				send()
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		conn.Close()
	}
}

func peerNames(peers []protocol.PeerInfo) map[string]bool {
	names := make(map[string]bool, len(peers))
	for _, p := range peers {
		names[p.Name] = true
	}
	return names
}
