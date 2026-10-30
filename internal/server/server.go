package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"lancollab/internal/protocol"
	"lancollab/internal/transport"
)

const (
	tlsHandshakeTimeout = 10 * time.Second
	helloTimeout        = 10 * time.Second
	authTimeout         = 30 * time.Second
	maxControlConns     = 512
	shutdownWait        = 3 * time.Second
)

// Server is the relay: TCP+TLS control plane on one port, UDP data plane on another.
type Server struct {
	tlsConfig *tls.Config
	ln        net.Listener
	udp       *net.UDPConn
	sm        *SessionManager
	ep        *transport.RDTEndpoint
	router    *Router
	logger    *log.Logger

	sessionTimeout time.Duration
	sweepEvery     time.Duration
	dropRate       float64
	fileQueueLimit int

	mu      sync.Mutex
	started bool
	closed  bool
	conns   map[net.Conn]struct{}
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewServer binds the TLS listener and the UDP socket (port 0 picks a free port).
func NewServer(tcpAddr, udpAddr string) (*Server, error) {
	cfg, err := protocol.NewServerTLSConfig()
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", tcpAddr, cfg)
	if err != nil {
		return nil, fmt.Errorf("listen TCP %s: %w", tcpAddr, err)
	}
	uaddr, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("resolve UDP %s: %w", udpAddr, err)
	}
	uconn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("listen UDP %s: %w", udpAddr, err)
	}
	// Larger socket buffers absorb bursts when 20 clients transfer files at once.
	_ = uconn.SetReadBuffer(4 << 20)
	_ = uconn.SetWriteBuffer(4 << 20)

	return &Server{
		tlsConfig:      cfg,
		ln:             ln,
		udp:            uconn,
		sm:             NewSessionManager(),
		logger:         log.New(os.Stderr, "[server] ", log.LstdFlags|log.Lmicroseconds),
		sessionTimeout: protocol.SessionTimeout,
		sweepEvery:     time.Second,
		conns:          make(map[net.Conn]struct{}),
		done:           make(chan struct{}),
	}, nil
}

// SetLogger replaces the logger (nil silences logging). Call before Start.
func (s *Server) SetLogger(l *log.Logger) {
	if l == nil {
		l = log.New(io.Discard, "", 0)
	}
	s.logger = l
}

// SetTimeouts sets the session timeout (default 10 s) and sweep period (default 1 s); call before Start.
func (s *Server) SetTimeouts(sessionTimeout, sweepEvery time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("server: SetTimeouts must be called before Start")
	}
	if sessionTimeout <= 0 || sweepEvery <= 0 {
		return errors.New("server: timeouts must be positive")
	}
	s.sessionTimeout = sessionTimeout
	s.sweepEvery = sweepEvery
	return nil
}

// SetFileQueueLimit sets the per-recipient queued-packet limit (default about 96 MiB); call before Start.
func (s *Server) SetFileQueueLimit(packets int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("server: SetFileQueueLimit must be called before Start")
	}
	if packets <= 0 {
		return errors.New("server: the file queue limit must be positive")
	}
	s.fileQueueLimit = packets
	return nil
}

// SetDropRate injects simulated loss (0..1) into the server's outgoing UDP datagrams.
func (s *Server) SetDropRate(rate float64) {
	s.mu.Lock()
	s.dropRate = rate
	ep := s.ep
	s.mu.Unlock()
	if ep != nil {
		ep.SetDropRate(rate)
	}
}

// Start launches the UDP engine, the router, the accept loop and the timeout sweeper.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return errors.New("server: already started or closed")
	}
	s.started = true
	s.ep = transport.NewRDTEndpoint(s.udp, s.resolveKey)
	s.ep.SetLocalID(protocol.ServerID)
	s.ep.SetDropRate(s.dropRate)
	s.router = NewRouter(s.sm, s.ep, s.logf)
	if s.fileQueueLimit > 0 {
		s.router.SetFileQueueLimit(s.fileQueueLimit)
	}
	s.mu.Unlock()

	s.router.Start()
	s.wg.Add(2)
	go s.acceptLoop()
	go s.sweepLoop()
	s.logf("control plane (TCP+TLS) on %s, data plane (UDP) on %s", s.TCPAddr(), s.UDPAddr())
	s.logf("TLS certificate SHA-256 fingerprint: %s", s.Fingerprint())
	return nil
}

// TCPAddr returns the bound control-plane address.
func (s *Server) TCPAddr() string { return s.ln.Addr().String() }

// UDPAddr returns the bound data-plane address.
func (s *Server) UDPAddr() string { return s.udp.LocalAddr().String() }

// Fingerprint returns the SHA-256 fingerprint of the in-memory TLS certificate.
func (s *Server) Fingerprint() string { return protocol.CertificateFingerprint(s.tlsConfig) }

// Sessions returns the number of signed-in clients.
func (s *Server) Sessions() int { return s.sm.Count() }

// Close stops listeners, ends all sessions and waits for goroutines; safe to call twice.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	ep, router := s.ep, s.router
	s.mu.Unlock()

	err := s.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	s.sm.CloseAll()
	if router != nil {
		router.Stop()
	}
	if ep != nil {
		_ = ep.Close()
	} else {
		_ = s.udp.Close()
	}
	if router != nil {
		router.Wait()
	}
	waitWithTimeout(&s.wg, shutdownWait)
	return err
}

func (s *Server) logf(format string, args ...any) {
	s.logger.Printf(format, args...)
}

// resolveKey is the RDT endpoint's KeyResolver: sender_id -> (session key, UDP address).
func (s *Server) resolveKey(senderID uint16) ([]byte, *net.UDPAddr, bool) {
	addr, key, ok := s.sm.Endpoint(senderID)
	return key, addr, ok
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if s.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			s.logf("accept error: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !s.trackConn(conn) {
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// handleConn runs one client's control FSM (HELLO, AUTH, PEER_UPDATE, LOGOUT); a panic here affects no one else.
func (s *Server) handleConn(raw net.Conn) {
	defer s.wg.Done()
	defer s.untrackConn(raw)
	defer raw.Close()
	defer func() {
		if rec := recover(); rec != nil {
			s.logf("recovered from panic while serving %s: %v", raw.RemoteAddr(), rec)
		}
	}()

	if tc, ok := raw.(*tls.Conn); ok {
		_ = tc.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
		if err := tc.Handshake(); err != nil {
			s.logf("TLS handshake with %s failed: %v", raw.RemoteAddr(), err)
			return
		}
		_ = tc.SetDeadline(time.Time{})
	}
	ctrl := transport.NewTLSControlConn(raw)

	hello, err := ctrl.Recv(helloTimeout)
	if err != nil {
		return
	}
	if hello.Type != protocol.CtrlHello || hello.Version != int(protocol.Version) || hello.UDPPort <= 0 || hello.UDPPort > 65535 {
		_ = ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlError, Reason: "expected HELLO with version 1 and a valid udp_port"})
		return
	}
	heartbeatSec := int(protocol.HeartbeatInterval / time.Second)
	if err := ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlHelloAck, Version: int(protocol.Version), HeartbeatSec: heartbeatSec}); err != nil {
		return
	}

	auth, err := ctrl.Recv(authTimeout)
	if err != nil {
		return
	}
	if auth.Type != protocol.CtrlAuthReq {
		_ = ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlError, Reason: "expected AUTH_REQ"})
		return
	}
	ip, tcpPort := splitRemote(raw.RemoteAddr())
	sess, err := s.sm.AuthenticateOrRegister(auth.Username, auth.Password, ip, tcpPort, hello.UDPPort, ctrl)
	if err != nil {
		s.logf("sign-in refused for %q from %s: %v", auth.Username, raw.RemoteAddr(), err)
		_ = ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlAuthRes, OK: false, Reason: err.Error()})
		return
	}

	s.ep.AllowPeer(sess.UserID)
	s.router.AddRecipient(sess)
	res := protocol.ControlMsg{
		Type:         protocol.CtrlAuthRes,
		OK:           true,
		UserID:       sess.UserID,
		SessionKey:   sess.SessionKey,
		HeartbeatSec: heartbeatSec,
		Peers:        s.sm.Peers(),
	}
	if err := ctrl.Send(res); err != nil {
		s.dropSession(sess.UserID, "could not send AUTH_RES")
		return
	}
	s.wg.Add(1)
	go s.controlWriter(sess)
	s.logf("%q signed in as #%d from %s (UDP port %d)", sess.Username, sess.UserID, raw.RemoteAddr(), hello.UDPPort)
	s.sm.BroadcastPeerUpdate()

	for {
		msg, err := ctrl.Recv(0)
		if err != nil {
			s.dropSession(sess.UserID, disconnectReason(err))
			return
		}
		switch msg.Type {
		case protocol.CtrlLogout:
			_ = ctrl.Send(protocol.ControlMsg{Type: protocol.CtrlLogout, OK: true})
			s.dropSession(sess.UserID, "signed out")
			return
		default:
			// Unknown control messages are ignored for forward compatibility.
		}
	}
}

// controlWriter writes one client's queued control messages, so broadcasts never block on a slow client.
func (s *Server) controlWriter(sess *ClientSession) {
	defer s.wg.Done()
	for {
		select {
		case <-sess.done:
			return
		case msg := <-sess.ctrlOut:
			if err := sess.Control.Send(msg); err != nil {
				s.dropSession(sess.UserID, "control write failed: "+err.Error())
				return
			}
		}
	}
}

// dropSession removes a session exactly once and tells everyone else.
func (s *Server) dropSession(userID uint16, reason string) {
	if !s.sm.RemoveSession(userID) {
		return
	}
	s.router.RemoveRecipient(userID)
	s.ep.ForgetPeer(userID)
	s.logf("#%d left: %s", userID, reason)
	s.sm.BroadcastPeerUpdate()
}

// sweepLoop removes clients whose heartbeats stopped (silent for > sessionTimeout).
func (s *Server) sweepLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			ids := s.sm.SweepTimeouts(s.sessionTimeout)
			for _, id := range ids {
				s.router.RemoveRecipient(id)
				s.ep.ForgetPeer(id)
				s.logf("#%d timed out: no packets for %v", id, s.sessionTimeout)
			}
			if len(ids) > 0 {
				s.sm.BroadcastPeerUpdate()
			}
		}
	}
}

func (s *Server) trackConn(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.conns) >= maxControlConns {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func splitRemote(addr net.Addr) (string, int) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func disconnectReason(err error) string {
	switch {
	case errors.Is(err, io.EOF):
		return "connection closed by client (EOF)"
	case errors.Is(err, net.ErrClosed):
		return "connection closed"
	default:
		return "connection error: " + err.Error()
	}
}

func waitWithTimeout(wg *sync.WaitGroup, d time.Duration) {
	ch := make(chan struct{})
	go func() {
		wg.Wait()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(d):
	}
}
