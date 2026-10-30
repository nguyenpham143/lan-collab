package transport

import (
	"bufio"
	"net"
	"sync"
	"time"

	"lancollab/internal/protocol"
)

// controlWriteTimeout bounds each control write so a peer that stops reading cannot block a writer forever.
const controlWriteTimeout = 5 * time.Second

// TLSControlConn adds length+JSON framing to a TLS conn; Send is concurrent-safe, Recv is single-reader.
type TLSControlConn struct {
	conn      net.Conn
	r         *bufio.Reader
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

// NewTLSControlConn wraps conn.
func NewTLSControlConn(conn net.Conn) *TLSControlConn {
	return &TLSControlConn{conn: conn, r: bufio.NewReaderSize(conn, 4096)}
}

// Send writes one control message (bounded by a 5 s write deadline).
func (c *TLSControlConn) Send(msg protocol.ControlMsg) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
	err := protocol.WriteControlMsg(c.conn, msg)
	_ = c.conn.SetWriteDeadline(time.Time{})
	return err
}

// Recv reads one message (timeout 0 waits forever); after any error the caller should Close.
func (c *TLSControlConn) Recv(timeout time.Duration) (protocol.ControlMsg, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if timeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	} else {
		_ = c.conn.SetReadDeadline(time.Time{})
	}
	return protocol.ReadControlMsg(c.r)
}

// Close closes the underlying connection. It is safe to call more than once.
func (c *TLSControlConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.conn.Close() })
	return c.closeErr
}

// RemoteAddr returns the peer address.
func (c *TLSControlConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}
