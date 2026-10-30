// Package server implements the relay: TLS control server, session registry and hop-by-hop UDP router.
package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	"lancollab/internal/protocol"
	"lancollab/internal/transport"
)

// Login errors. Their text is sent to the client in AUTH_RES.reason.
var (
	ErrBadCredentials  = errors.New("wrong password for this username")
	ErrAlreadyOnline   = errors.New("this user is already signed in from another client")
	ErrServerFull      = errors.New("the server has reached its maximum number of sessions")
	ErrInvalidUsername = errors.New("username must be 1-32 characters: letters, digits, '.', '_' or '-'")
	ErrInvalidPassword = errors.New("password must be 1-128 bytes")
)

const defaultMaxSessions = 256

// ClientSession is one signed-in client; UDPAddr, UDPPort and LastSeen change and go through SessionManager.
type ClientSession struct {
	UserID     uint16
	Username   string
	IP         string
	TCPPort    int
	UDPPort    int
	UDPAddr    *net.UDPAddr
	SessionKey []byte
	Control    *transport.TLSControlConn
	LastSeen   time.Time

	ctrlOut   chan protocol.ControlMsg // queued control messages (written by one writer goroutine)
	done      chan struct{}            // closed when the session ends
	closeOnce sync.Once
}

// Done is closed when the session has ended.
func (s *ClientSession) Done() <-chan struct{} { return s.done }

// shutdown wakes the session's goroutines and closes its control connection, which unblocks Recv.
func (s *ClientSession) shutdown() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.Control != nil {
			_ = s.Control.Close()
		}
	})
}

// enqueueControl never blocks; when full it drops the oldest message (PEER_UPDATE is a full snapshot).
func (s *ClientSession) enqueueControl(msg protocol.ControlMsg) bool {
	select {
	case <-s.done:
		return false
	default:
	}
	for attempt := 0; attempt < 2; attempt++ {
		select {
		case s.ctrlOut <- msg:
			return true
		default:
			select {
			case <-s.ctrlOut:
			default:
			}
		}
	}
	return false
}

type userRecord struct {
	salt [16]byte
	hash [32]byte
}

// SessionManager keeps accounts and sessions in memory; safe for concurrent use.
type SessionManager struct {
	mu          sync.RWMutex
	users       map[string]userRecord
	sessions    map[uint16]*ClientSession
	byName      map[string]uint16
	nextID      uint16
	maxSessions int
}

// NewSessionManager returns an empty manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		users:       make(map[string]userRecord),
		sessions:    make(map[uint16]*ClientSession),
		byName:      make(map[string]uint16),
		nextID:      1,
		maxSessions: defaultMaxSessions,
	}
}

// AuthenticateOrRegister signs in (registering unknown names) with a never-reused UserID and a fresh 32-byte key.
func (m *SessionManager) AuthenticateOrRegister(username, password, ip string, tcpPort, udpPort int, ctrl *transport.TLSControlConn) (*ClientSession, error) {
	if !validUsername(username) {
		return nil, ErrInvalidUsername
	}
	if len(password) == 0 || len(password) > 128 {
		return nil, ErrInvalidPassword
	}
	key, err := protocol.GenerateSessionKey()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rec, exists := m.users[username]
	if exists {
		h := hashPassword(rec.salt, password)
		if subtle.ConstantTimeCompare(h[:], rec.hash[:]) != 1 {
			return nil, ErrBadCredentials
		}
	} else {
		if _, err := rand.Read(rec.salt[:]); err != nil {
			return nil, err
		}
		rec.hash = hashPassword(rec.salt, password)
	}
	if _, online := m.byName[username]; online {
		return nil, ErrAlreadyOnline
	}
	if len(m.sessions) >= m.maxSessions {
		return nil, ErrServerFull
	}
	id, ok := m.allocateIDLocked()
	if !ok {
		return nil, ErrServerFull
	}
	if !exists {
		m.users[username] = rec // register only once the sign-in has fully succeeded
	}
	sess := &ClientSession{
		UserID:     id,
		Username:   username,
		IP:         ip,
		TCPPort:    tcpPort,
		UDPPort:    udpPort,
		UDPAddr:    &net.UDPAddr{IP: net.ParseIP(ip), Port: udpPort},
		SessionKey: key,
		Control:    ctrl,
		LastSeen:   time.Now(),
		ctrlOut:    make(chan protocol.ControlMsg, 8),
		done:       make(chan struct{}),
	}
	m.sessions[id] = sess
	m.byName[username] = id
	return sess, nil
}

// allocateIDLocked returns the next free UserID in 1..0xFFFE. m.mu must be held.
func (m *SessionManager) allocateIDLocked() (uint16, bool) {
	for i := 0; i < 0xFFFE; i++ {
		id := m.nextID
		m.nextID++
		if m.nextID == 0 || m.nextID == protocol.BroadcastTarget {
			m.nextID = 1
		}
		if id == protocol.ServerID || id == protocol.BroadcastTarget {
			continue
		}
		if _, used := m.sessions[id]; !used {
			return id, true
		}
	}
	return 0, false
}

// UpdateHeartbeat records that an authenticated packet arrived from userID at udpAddr.
func (m *SessionManager) UpdateHeartbeat(userID uint16, udpAddr *net.UDPAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[userID]
	if s == nil {
		return
	}
	s.LastSeen = time.Now()
	if udpAddr != nil && (s.UDPAddr == nil || s.UDPAddr.String() != udpAddr.String()) {
		c := *udpAddr
		c.IP = append(net.IP(nil), udpAddr.IP...)
		s.UDPAddr = &c
		s.UDPPort = udpAddr.Port
	}
}

// RemoveSession ends a session and reports whether it existed, so only one caller cleans up.
func (m *SessionManager) RemoveSession(userID uint16) bool {
	m.mu.Lock()
	s := m.sessions[userID]
	if s != nil {
		delete(m.sessions, userID)
		if m.byName[s.Username] == userID {
			delete(m.byName, s.Username)
		}
	}
	m.mu.Unlock()
	if s == nil {
		return false
	}
	s.shutdown()
	return true
}

// SweepTimeouts ends every session silent for longer than maxIdle and returns their IDs.
func (m *SessionManager) SweepTimeouts(maxIdle time.Duration) []uint16 {
	now := time.Now()
	var expired []*ClientSession
	m.mu.Lock()
	for id, s := range m.sessions {
		if now.Sub(s.LastSeen) > maxIdle {
			expired = append(expired, s)
			delete(m.sessions, id)
			if m.byName[s.Username] == id {
				delete(m.byName, s.Username)
			}
		}
	}
	m.mu.Unlock()

	ids := make([]uint16, 0, len(expired))
	for _, s := range expired {
		s.shutdown()
		ids = append(ids, s.UserID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// BroadcastPeerUpdate pushes the current peer list to every session without blocking.
func (m *SessionManager) BroadcastPeerUpdate() {
	msg := protocol.ControlMsg{Type: protocol.CtrlPeerUpdate, Peers: m.Peers()}
	m.mu.RLock()
	targets := make([]*ClientSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		targets = append(targets, s)
	}
	m.mu.RUnlock()
	for _, s := range targets {
		s.enqueueControl(msg)
	}
}

// Get returns the session for userID.
func (m *SessionManager) Get(userID uint16) (*ClientSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[userID]
	return s, ok
}

// Endpoint returns the current UDP address and session key of userID.
func (m *SessionManager) Endpoint(userID uint16) (*net.UDPAddr, []byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[userID]
	if !ok || s.UDPAddr == nil {
		return nil, nil, false
	}
	c := *s.UDPAddr
	c.IP = append(net.IP(nil), s.UDPAddr.IP...)
	return &c, s.SessionKey, true
}

// OnlineIDs returns the IDs of all sessions in ascending order.
func (m *SessionManager) OnlineIDs() []uint16 {
	m.mu.RLock()
	ids := make([]uint16, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.RUnlock()
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Peers returns the online users sorted by ID.
func (m *SessionManager) Peers() []protocol.PeerInfo {
	m.mu.RLock()
	peers := make([]protocol.PeerInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		peers = append(peers, protocol.PeerInfo{ID: s.UserID, Name: s.Username, IP: s.IP, UDPPort: s.UDPPort})
	}
	m.mu.RUnlock()
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	return peers
}

// Count returns the number of active sessions.
func (m *SessionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// CloseAll ends every session (used on server shutdown).
func (m *SessionManager) CloseAll() {
	m.mu.Lock()
	all := make([]*ClientSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.sessions = make(map[uint16]*ClientSession)
	m.byName = make(map[string]uint16)
	m.mu.Unlock()
	for _, s := range all {
		s.shutdown()
	}
}

// hashPassword returns SHA-256(salt || password); production code would use a slow KDF.
func hashPassword(salt [16]byte, password string) [32]byte {
	buf := make([]byte, 0, len(salt)+len(password))
	buf = append(buf, salt[:]...)
	buf = append(buf, password...)
	return sha256.Sum256(buf)
}

func validUsername(name string) bool {
	if len(name) == 0 || len(name) > 32 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
