package tests

import (
	"io"
	"log"
	"testing"
	"time"

	"lancollab/internal/client"
	"lancollab/internal/server"
)

// startServer runs a quiet server on free loopback ports; configure may adjust it before Start.
func startServer(t *testing.T, configure func(*server.Server)) *server.Server {
	t.Helper()
	srv, err := server.NewServer("127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetLogger(log.New(io.Discard, "", 0))
	if configure != nil {
		configure(srv)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// newClientDir signs in a controller and returns it with its download directory.
func newClientDir(t *testing.T, srv *server.Server, name string) (*client.Controller, string) {
	t.Helper()
	host, tcpPort := splitHostPort(t, srv.TCPAddr())
	_, udpPort := splitHostPort(t, srv.UDPAddr())
	dir := t.TempDir()
	c := client.NewController(host, tcpPort, udpPort)
	c.SetDownloadDir(dir)
	if err := c.ConnectAndLogin(name, "pw-"+name); err != nil {
		t.Fatalf("%s could not sign in: %v", name, err)
	}
	t.Cleanup(func() { _ = c.Logout() })
	return c, dir
}

func newClient(t *testing.T, srv *server.Server, name string) *client.Controller {
	t.Helper()
	c, _ := newClientDir(t, srv, name)
	return c
}

// subscribe returns the controller's event stream and unsubscribes when the test ends.
func subscribe(t *testing.T, c *client.Controller) <-chan client.ClientEvent {
	t.Helper()
	ch := c.SubscribeEvents()
	t.Cleanup(func() { c.UnsubscribeEvents(ch) })
	return ch
}

// waitPeers blocks until c sees at least n users online.
func waitPeers(t *testing.T, c *client.Controller, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(c.Peers()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s sees %d of %d users after 10 s", c.Username(), len(c.Peers()), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitEvent returns the first event for which pred is true, or fails after d.
func waitEvent(t *testing.T, ch <-chan client.ClientEvent, d time.Duration, what string, pred func(client.ClientEvent) bool) client.ClientEvent {
	t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("event stream closed while waiting for %s", what)
			}
			if pred(ev) {
				return ev
			}
		case <-timer.C:
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
	}
}
