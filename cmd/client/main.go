// Command client runs a LanCollab client with a browser UI (default) or a console UI.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"lancollab/internal/client"
	"lancollab/internal/protocol"
)

func main() {
	serverHost := flag.String("server", "127.0.0.1", "server host name or IP address")
	tcpPort := flag.Int("tcp", protocol.DefaultTCPPort, "server control-plane (TCP+TLS) port")
	udpPort := flag.Int("udp", protocol.DefaultUDPPort, "server data-plane (UDP) port")
	ui := flag.String("ui", "http", "user interface: http (browser) or console")
	httpAddr := flag.String("http", "127.0.0.1:8080", "browser UI address; if the port is busy the next free one (up to +19) is used")
	user := flag.String("user", "", "username (console UI prompts if empty; browser UI signs in automatically if set with -pass)")
	pass := flag.String("pass", "", "password")
	pin := flag.String("pin", "", "expected SHA-256 fingerprint of the server TLS certificate (printed by the server)")
	downloads := flag.String("downloads", "downloads", "directory for received files")
	loss := flag.Float64("loss", 0, "simulated loss rate for outgoing UDP datagrams, 0..1 (testing only)")
	flag.Parse()

	ctrl := client.NewController(*serverHost, *tcpPort, *udpPort)
	ctrl.SetDownloadDir(*downloads)
	ctrl.SetServerFingerprint(*pin)
	ctrl.SetDropRate(*loss)

	switch *ui {
	case "console":
		if err := client.RunConsole(ctrl, os.Stdin, os.Stdout, *user, *pass); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "http":
		bridge, err := startBridge(*httpAddr, ctrl)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot start the browser UI:", err)
			os.Exit(1)
		}
		fmt.Printf("LanCollab client: open http://%s in your browser (server %s).\n", bridge.Addr(), ctrl.ServerAddress())
		if *user != "" && *pass != "" {
			if err := ctrl.ConnectAndLogin(*user, *pass); err != nil {
				fmt.Fprintln(os.Stderr, "automatic sign-in failed:", err)
			} else {
				fmt.Printf("Signed in as %s (#%d).\n", ctrl.Username(), ctrl.UserID())
			}
		}
		fmt.Println("Press Ctrl+C to quit.")
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		_ = ctrl.Logout()
		_ = bridge.Close()
	default:
		fmt.Fprintf(os.Stderr, "unknown -ui %q (use http or console)\n", *ui)
		os.Exit(2)
	}
}

// startBridge tries addr and the next 19 ports, so several clients can run on one machine.
func startBridge(addr string, ctrl *client.Controller) (*client.HTTPBridge, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in %q", addr)
	}
	attempts := 20
	if port == 0 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		b, err := client.StartHTTPBridge(net.JoinHostPort(host, strconv.Itoa(port+i)), ctrl)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
