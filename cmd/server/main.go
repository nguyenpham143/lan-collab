// Command server runs the LanCollab relay (TCP+TLS :9000, UDP :9001).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lancollab/internal/protocol"
	"lancollab/internal/server"
)

func main() {
	tcpAddr := flag.String("tcp", fmt.Sprintf("0.0.0.0:%d", protocol.DefaultTCPPort), "control-plane (TCP+TLS) listen address")
	udpAddr := flag.String("udp", fmt.Sprintf("0.0.0.0:%d", protocol.DefaultUDPPort), "data-plane (UDP) listen address")
	loss := flag.Float64("loss", 0, "simulated loss rate for outgoing UDP datagrams, 0..1 (testing only)")
	timeout := flag.Duration("timeout", protocol.SessionTimeout, "remove a client after this long without UDP packets")
	flag.Parse()

	srv, err := server.NewServer(*tcpAddr, *udpAddr)
	if err != nil {
		log.Fatalf("cannot start server: %v", err)
	}
	if *timeout != protocol.SessionTimeout {
		if err := srv.SetTimeouts(*timeout, time.Second); err != nil {
			log.Fatalf("invalid -timeout: %v", err)
		}
	}
	srv.SetDropRate(*loss)
	if err := srv.Start(); err != nil {
		log.Fatalf("cannot start server: %v", err)
	}

	fmt.Printf("LanCollab server is running.\n")
	fmt.Printf("  control plane (TCP+TLS): %s\n", srv.TCPAddr())
	fmt.Printf("  data plane (UDP):        %s\n", srv.UDPAddr())
	fmt.Printf("  TLS fingerprint:         %s\n", srv.Fingerprint())
	fmt.Printf("  clients can pin it with: -pin %s\n", srv.Fingerprint())
	if *loss > 0 {
		fmt.Printf("  simulated UDP loss:      %.0f%%\n", *loss*100)
	}
	fmt.Printf("Press Ctrl+C to stop.\n")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("Shutting down...")
	_ = srv.Close()
}
