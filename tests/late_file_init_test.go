package tests

import (
	"strings"
	"testing"
	"time"

	"lancollab/internal/client"
)

// waitUntil polls cond every 10 ms until it is true or d has passed.
func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A FILE_INIT arriving after the sender's "user left" notice must fail at once, not stay "receiving".
func TestFileInitArrivingAfterSenderLeftFailsAtOnce(t *testing.T) {
	srv := startServer(t, nil)
	alice := newClient(t, srv, "alice")
	bob := newClient(t, srv, "bob")
	waitPeers(t, alice, 2)
	waitPeers(t, bob, 2)

	// 1. Bob's ACKs are lost, so file 1 fills the server's window to Bob and the rest waits in his queue.
	bob.SetDropRate(1)
	first, err := alice.SendFile(bob.UserID(), "first.bin", make([]byte, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 3*time.Second, "file 1 to reach the server", func() bool {
		tp, ok := transferOf(alice, first, client.DirectionSend)
		return ok && tp.Stage == client.StageAwaitingConfirm
	})

	// 2. File 2 starts; its FILE_INIT and first chunks queue on the server behind file 1.
	second, err := alice.SendFile(bob.UserID(), "second.bin", make([]byte, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 3*time.Second, "file 2 to start", func() bool {
		tp, ok := transferOf(alice, second, client.DirectionSend)
		return ok && tp.Transferred > 0
	})
	time.Sleep(50 * time.Millisecond)

	// 3. Alice leaves. Bob learns it over TCP while file 2's FILE_INIT is still queued.
	_ = alice.Logout()
	waitUntil(t, 3*time.Second, "bob to see alice leave", func() bool { return len(bob.Peers()) == 1 })
	if _, known := transferOf(bob, second, client.DirectionRecv); known {
		t.Skip("FILE_INIT overtook PEER_UPDATE in this run; the late-arrival order was not reproduced")
	}

	// 4. Bob's link recovers and the server delivers the queued FILE_INIT.
	bob.SetDropRate(0)
	waitUntil(t, 6*time.Second, "file 2's FILE_INIT to reach bob", func() bool {
		_, ok := transferOf(bob, second, client.DirectionRecv)
		return ok
	})
	tp := waitTransferStage(t, bob, second, client.DirectionRecv, client.StageFailed, time.Second)
	if !strings.Contains(tp.Error, "offline") {
		t.Fatalf("the receiver should say the sender is offline, got %q", tp.Error)
	}
}

// If the sender's network dies while it still looks online, the idle timeout fails the transfer and tells the sender.
func TestStalledIncomingTransferTimesOut(t *testing.T) {
	srv := startServer(t, nil)
	alice := newClient(t, srv, "alice")
	bob := newClient(t, srv, "bob")
	bob.SetTransferIdleTimeout(time.Second)
	waitPeers(t, alice, 2)
	waitPeers(t, bob, 2)

	stream, err := alice.SendFile(bob.UserID(), "stalled.bin", make([]byte, 8<<20))
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, "bob to start receiving", func() bool {
		tp, ok := transferOf(bob, stream, client.DirectionRecv)
		return ok && tp.Stage == client.StageReceiving && tp.Percent > 0
	})

	alice.SetDropRate(1) // every packet alice sends is lost from now on
	start := time.Now()
	tp := waitTransferStage(t, bob, stream, client.DirectionRecv, client.StageFailed, 5*time.Second)
	if !strings.Contains(tp.Error, "no data received") {
		t.Fatalf("unexpected reason %q", tp.Error)
	}
	if len(bob.Peers()) != 2 {
		t.Fatal("alice should still be listed online: the timeout, not presence, must catch this")
	}
	t.Logf("bob gave up %v after alice's link died: %s", time.Since(start).Round(100*time.Millisecond), tp.Error)

	// The failure FILE_DONE reaches alice (her incoming packets still arrive).
	sent := waitTransferStage(t, alice, stream, client.DirectionSend, client.StageFailed, 3*time.Second)
	if !strings.Contains(sent.Error, "no data received") {
		t.Fatalf("alice should learn why, got %q", sent.Error)
	}
}

// A transfer that keeps receiving data, however slowly, must not time out.
func TestSlowButSteadyTransferDoesNotTimeOut(t *testing.T) {
	srv := startServer(t, nil)
	alice := newClient(t, srv, "alice")
	bob := newClient(t, srv, "bob")
	// Longer than the maximum RTO (2 s), the longest normal gap between two chunks.
	bob.SetTransferIdleTimeout(3 * time.Second)
	waitPeers(t, alice, 2)
	waitPeers(t, bob, 2)

	alice.SetDropRate(0.3) // heavy loss: slow, but chunks keep arriving
	data := make([]byte, 600<<10)
	for i := range data {
		data[i] = byte(i * 7)
	}
	stream, err := alice.SendFile(bob.UserID(), "slow.bin", data)
	if err != nil {
		t.Fatal(err)
	}
	waitTransferStage(t, bob, stream, client.DirectionRecv, client.StageVerified, 60*time.Second)
}
