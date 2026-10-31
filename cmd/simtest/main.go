// Command simtest runs a server and N clients in one process with UDP loss and checks every message and file arrives.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"text/tabwriter"
	"time"

	"lancollab/internal/client"
	"lancollab/internal/protocol"
	"lancollab/internal/server"
)

type clientResult struct {
	name      string
	userID    uint16
	chats     int  // broadcast messages received from other clients
	sentOK    bool // FILE_DONE ok received for the file this client sent
	recvOK    bool // the file sent to this client was reassembled and verified
	failure   string
	retrans   uint64
	rttMicros int64
	cwnd      int
}

func main() { os.Exit(run()) }

// run returns the process exit code, so deferred cleanup always runs.
func run() int {
	numClients := flag.Int("clients", 20, "number of concurrent clients")
	loss := flag.Float64("loss", 0.10, "simulated loss rate on every UDP endpoint, 0..1")
	fileSize := flag.Int("filesize", 20*1024, "size in bytes of the file each client sends")
	timeout := flag.Duration("timeout", 60*time.Second, "give up after this long")
	verbose := flag.Bool("v", false, "show server logs")
	flag.Parse()

	n := *numClients
	if n < 2 {
		fmt.Fprintln(os.Stderr, "-clients must be at least 2")
		return 2
	}

	srv, err := server.NewServer("127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return 1
	}
	if !*verbose {
		srv.SetLogger(log.New(io.Discard, "", 0))
	}
	srv.SetDropRate(*loss)
	if err := srv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return 1
	}
	defer srv.Close()

	host, tcpPort := splitHostPort(srv.TCPAddr())
	_, udpPort := splitHostPort(srv.UDPAddr())
	tmp, err := os.MkdirTemp("", "lancollab-simtest-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(tmp)

	fmt.Printf("Simulating %d clients, %.0f%% UDP loss on every endpoint, %d-byte files\n", n, *loss*100, *fileSize)

	// 1. Sign everyone in concurrently.
	ctrls := make([]*client.Controller, n)
	loginErrs := make([]error, n)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := client.NewController(host, tcpPort, udpPort)
			c.SetDropRate(*loss)
			c.SetDownloadDir(filepath.Join(tmp, fmt.Sprintf("sim_%02d", i+1)))
			loginErrs[i] = c.ConnectAndLogin(fmt.Sprintf("sim_%02d", i+1), "pass123")
			ctrls[i] = c
		}(i)
	}
	wg.Wait()
	defer func() {
		for _, c := range ctrls {
			if c != nil {
				_ = c.Logout()
			}
		}
	}()
	for i, err := range loginErrs {
		if err != nil {
			fmt.Fprintf(os.Stderr, "client %d could not sign in: %v\n", i+1, err)
			return 1
		}
	}
	loginTime := time.Since(start)

	// 2. Wait until every client sees all n users online.
	deadline := time.Now().Add(*timeout)
	for _, c := range ctrls {
		for len(c.Peers()) < n {
			if time.Now().After(deadline) {
				fmt.Fprintf(os.Stderr, "%s sees only %d of %d users\n", c.Username(), len(c.Peers()), n)
				return 1
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// 3. Every client broadcasts one message and sends one file to the next client.
	results := make([]*clientResult, n)
	payloads := make([][]byte, n)
	rng := rand.New(rand.NewSource(42))
	for i, c := range ctrls {
		results[i] = &clientResult{name: c.Username(), userID: c.UserID()}
		payloads[i] = make([]byte, *fileSize)
		for j := range payloads[i] {
			payloads[i][j] = byte(rng.Intn(256))
		}
	}
	var mu sync.Mutex
	allDone := make(chan struct{})
	var doneOnce sync.Once
	complete := func() bool {
		for _, r := range results {
			if r.chats < n-1 || !r.sentOK || !r.recvOK {
				return false
			}
		}
		return true
	}

	for i, c := range ctrls {
		events := c.SubscribeEvents()
		go func(r *clientResult, events <-chan client.ClientEvent) {
			for ev := range events {
				mu.Lock()
				switch ev.Kind {
				case client.EventChat:
					if !ev.Self && !ev.Direct {
						r.chats++
					}
				case client.EventFileProgress:
					if p := ev.Progress; p != nil {
						switch {
						case p.Stage == client.StageVerified && p.Direction == client.DirectionSend:
							r.sentOK = true
						case p.Stage == client.StageVerified && p.Direction == client.DirectionRecv:
							r.recvOK = true
						case p.Stage == client.StageFailed:
							r.failure = p.Error
						}
					}
				}
				finished := complete()
				mu.Unlock()
				if finished {
					doneOnce.Do(func() { close(allDone) })
				}
			}
		}(results[i], events)
	}

	sendStart := time.Now()
	for i, c := range ctrls {
		wg.Add(1)
		go func(i int, c *client.Controller) {
			defer wg.Done()
			if err := c.SendChat(protocol.BroadcastTarget, "hello from "+c.Username()); err != nil {
				log.Printf("%s: chat failed: %v", c.Username(), err)
			}
			target := ctrls[(i+1)%n].UserID()
			if _, err := c.SendFile(target, fmt.Sprintf("sim_%02d.bin", i+1), payloads[i]); err != nil {
				log.Printf("%s: file failed: %v", c.Username(), err)
			}
		}(i, c)
	}
	wg.Wait()

	ok := true
	select {
	case <-allDone:
	case <-time.After(time.Until(deadline)):
		ok = false
	}
	elapsed := time.Since(sendStart)

	// 4. Verify the bytes on disk as well, then report.
	for i := range ctrls {
		recvFrom := (i - 1 + n) % n
		path := filepath.Join(tmp, fmt.Sprintf("sim_%02d", i+1), fmt.Sprintf("sim_%02d.bin", recvFrom+1))
		data, err := os.ReadFile(path)
		mu.Lock()
		if err != nil || !bytes.Equal(data, payloads[recvFrom]) {
			results[i].recvOK = false
			if results[i].failure == "" {
				results[i].failure = "file on disk missing or different"
			}
			ok = false
		}
		mu.Unlock()
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "client\tid\tchats\tfile sent\tfile received\tretrans\tRTT (ms)\tcwnd\tnote")
	mu.Lock()
	for i, r := range results {
		if st, have := ctrls[i].Stats(); have {
			r.retrans, r.rttMicros, r.cwnd = st.Retransmissions, st.RTTMicros, st.Cwnd
		}
		fmt.Fprintf(tw, "%s\t%d\t%d/%d\t%s\t%s\t%d\t%.2f\t%d\t%s\n",
			r.name, r.userID, r.chats, n-1, yesNo(r.sentOK), yesNo(r.recvOK), r.retrans, float64(r.rttMicros)/1000, r.cwnd, r.failure)
	}
	mu.Unlock()
	tw.Flush()

	fmt.Printf("\nSign-in of %d clients: %v\n", n, loginTime.Round(time.Millisecond))
	fmt.Printf("All chats and files delivered in: %v\n", elapsed.Round(time.Millisecond))
	if !ok {
		fmt.Println("RESULT: FAIL")
		return 1
	}
	fmt.Println("RESULT: PASS")
	return 0
}

func yesNo(b bool) string {
	if b {
		return "verified"
	}
	return "MISSING"
}

// splitHostPort splits an address returned by the server, which is always valid.
func splitHostPort(addr string) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	return host, port
}
