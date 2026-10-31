package client

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"lancollab/internal/protocol"
)

const consoleHelp = `Commands:
  <text>                 send <text> to everyone
  /msg <id> <text>       send a direct message to user <id>
  /send <id> <path>      send a file to user <id>
  /peers                 list online users
  /transfers             list file transfers
  /stats                 show link statistics (RTT, cwnd, rwnd, retransmissions)
  /help                  show this help
  /quit                  sign out and exit`

// syncWriter serialises writes from the input loop and the event printer.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) printf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.w, format, args...)
}

// RunConsole signs in and drives the controller from a terminal until /quit (empty credentials are prompted).
func RunConsole(ctrl *Controller, in io.Reader, out io.Writer, username, password string) error {
	w := &syncWriter{w: out}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 64*1024)

	prompt := func(label string) (string, bool) {
		w.printf("%s: ", label)
		if !sc.Scan() {
			return "", false
		}
		return strings.TrimSpace(sc.Text()), true
	}
	var ok bool
	if username == "" {
		if username, ok = prompt("Username"); !ok {
			return io.EOF
		}
	}
	if password == "" {
		if password, ok = prompt("Password"); !ok {
			return io.EOF
		}
	}

	w.printf("Connecting to %s ...\n", ctrl.ServerAddress())
	if err := ctrl.ConnectAndLogin(username, password); err != nil {
		return err
	}
	w.printf("Signed in as %s (#%d). Type /help for commands.\n", ctrl.Username(), ctrl.UserID())

	events := ctrl.SubscribeEvents()
	printerDone := make(chan struct{})
	go func() {
		defer close(printerDone)
		printConsoleEvents(events, w)
	}()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			if err := ctrl.SendChat(protocol.BroadcastTarget, line); err != nil {
				w.printf("! %v\n", err)
			}
			continue
		}
		cmd, rest, _ := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		switch cmd {
		case "/help":
			w.printf("%s\n", consoleHelp)
		case "/peers":
			for _, p := range ctrl.Peers() {
				me := ""
				if p.ID == ctrl.UserID() {
					me = " (you)"
				}
				w.printf("  #%-5d %-20s %s:%d%s\n", p.ID, p.Name, p.IP, p.UDPPort, me)
			}
		case "/msg":
			idStr, text, _ := strings.Cut(rest, " ")
			id, err := parseUserID(idStr)
			if err != nil {
				w.printf("! usage: /msg <id> <text>\n")
				continue
			}
			if err := ctrl.SendChat(id, text); err != nil {
				w.printf("! %v\n", err)
			}
		case "/send":
			idStr, filePath, _ := strings.Cut(rest, " ")
			id, err := parseUserID(idStr)
			filePath = strings.Trim(strings.TrimSpace(filePath), `"`)
			if err != nil || filePath == "" {
				w.printf("! usage: /send <id> <path>\n")
				continue
			}
			data, err := os.ReadFile(filePath)
			if err != nil {
				w.printf("! cannot read %s: %v\n", filePath, err)
				continue
			}
			stream, err := ctrl.SendFile(id, filepath.Base(filePath), data)
			if err != nil {
				w.printf("! %v\n", err)
				continue
			}
			w.printf("  sending %s (%d bytes) to #%d on stream %d\n", filepath.Base(filePath), len(data), id, stream)
		case "/transfers":
			for _, tp := range ctrl.Transfers() {
				w.printf("  [%s] %-30s %3d%%  %s  peer #%d  stream %d %s\n", tp.Direction, tp.Filename, tp.Percent, tp.Stage, tp.PeerID, tp.StreamID, tp.Error)
			}
		case "/stats":
			if st, ok := ctrl.Stats(); ok {
				w.printf("  RTT %.2f ms | RTO %d ms | cwnd %d | ssthresh %d | peer rwnd %d | in flight %d | retransmissions %d | sent %d | acked %d\n",
					float64(st.RTTMicros)/1000, st.RTOMillis, st.Cwnd, st.Ssthresh, st.PeerRwnd, st.InFlight, st.Retransmissions, st.PacketsSent, st.PacketsAcked)
			} else {
				w.printf("  not signed in\n")
			}
		case "/quit", "/exit":
			_ = ctrl.Logout()
			ctrl.UnsubscribeEvents(events)
			<-printerDone
			w.printf("Signed out.\n")
			return nil
		default:
			w.printf("! unknown command %s (try /help)\n", cmd)
		}
	}
	_ = ctrl.Logout()
	ctrl.UnsubscribeEvents(events)
	<-printerDone
	return sc.Err()
}

func parseUserID(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(s), "#"), 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}

// printConsoleEvents prints one line per event; file progress at start, every 25 % and at the end.
func printConsoleEvents(events <-chan ClientEvent, w *syncWriter) {
	lastBucket := make(map[string]int)
	lastStage := make(map[string]string)
	for ev := range events {
		switch ev.Kind {
		case EventChat:
			if ev.Self {
				continue // already typed by the user
			}
			ts := time.UnixMilli(ev.TS).Format("15:04:05")
			if ev.Direct {
				w.printf("[%s] (direct) %s: %s\n", ts, ev.From, ev.Text)
			} else {
				w.printf("[%s] %s: %s\n", ts, ev.From, ev.Text)
			}
		case EventPeers:
			names := make([]string, 0, len(ev.Peers))
			for _, p := range ev.Peers {
				names = append(names, fmt.Sprintf("%s#%d", p.Name, p.ID))
			}
			w.printf("* online: %s\n", strings.Join(names, ", "))
		case EventFileProgress:
			tp := ev.Progress
			if tp == nil {
				continue
			}
			key := transferKey(tp.Direction, tp.PeerID, tp.StreamID)
			bucket := tp.Percent / 25
			if tp.Stage == lastStage[key] && bucket == lastBucket[key] {
				continue
			}
			lastStage[key], lastBucket[key] = tp.Stage, bucket
			arrow := "->"
			if tp.Direction == DirectionRecv {
				arrow = "<-"
			}
			line := fmt.Sprintf("* file %s %s #%d: %d%% (%s)", tp.Filename, arrow, tp.PeerID, tp.Percent, tp.Stage)
			if tp.SavedPath != "" {
				line += " saved to " + tp.SavedPath
			}
			if tp.Error != "" {
				line += " - " + tp.Error
			}
			w.printf("%s\n", line)
		case EventState:
			if ev.State == StateDisconnected && ev.Error != "" {
				w.printf("* disconnected: %s\n", ev.Error)
			}
		case EventError:
			w.printf("! server: %s\n", ev.Error)
		}
	}
}
