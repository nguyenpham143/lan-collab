package client

import (
	"bufio"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"lancollab/internal/protocol"
)

// The browser UI is compiled into the binary.
//
//go:embed static/index.html static/style.css static/app.js
var staticFiles embed.FS

const (
	maxRequestLineBytes = 8 << 10
	maxHeaderBytes      = 32 << 10
	maxHeaderLines      = 100
	maxBodyBytes        = 96 << 20 // a 64 MiB file is about 86 MiB once base64-encoded
	requestReadTimeout  = 60 * time.Second
	responseTimeout     = 30 * time.Second
	sseKeepAlive        = 15 * time.Second
)

// maxSimulatedLoss caps the demo slider; at 100% nothing gets through and the session times out.
const maxSimulatedLoss = 0.95

// imageTypes may be shown inline; SVG is excluded because it can carry script.
var imageTypes = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
	".bmp":  "image/bmp",
}

var (
	errHeaderTooLarge = errors.New("request header too large")
	errMalformed      = errors.New("malformed HTTP request")
)

// HTTPBridge is a hand-written HTTP/1.1 server (no net/http) serving the UI, an SSE event stream and a JSON API.
type HTTPBridge struct {
	ln       net.Listener
	ctrl     *Controller
	loopback bool

	mu    sync.Mutex
	conns map[net.Conn]struct{}

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type httpRequest struct {
	Method  string
	Path    string
	Query   string
	Headers map[string]string // lower-case names
	Body    []byte
}

// StartHTTPBridge listens on listenAddr (for example "127.0.0.1:8080") and serves the UI.
func StartHTTPBridge(listenAddr string, ctrl *Controller) (*HTTPBridge, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	b := &HTTPBridge{
		ln:    ln,
		ctrl:  ctrl,
		conns: make(map[net.Conn]struct{}),
		done:  make(chan struct{}),
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		b.loopback = tcp.IP.IsLoopback()
	}
	b.wg.Add(1)
	go b.acceptLoop()
	return b, nil
}

// Addr returns the listening address.
func (b *HTTPBridge) Addr() string { return b.ln.Addr().String() }

// Close stops the listener and every open connection, including SSE streams.
func (b *HTTPBridge) Close() error {
	var err error
	b.closeOnce.Do(func() {
		close(b.done)
		err = b.ln.Close()
		b.mu.Lock()
		for c := range b.conns {
			_ = c.Close()
		}
		b.mu.Unlock()
		b.wg.Wait()
	})
	return err
}

func (b *HTTPBridge) acceptLoop() {
	defer b.wg.Done()
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			select {
			case <-b.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		b.mu.Lock()
		b.conns[conn] = struct{}{}
		b.mu.Unlock()
		b.wg.Add(1)
		go b.serveConn(conn)
	}
}

func (b *HTTPBridge) serveConn(conn net.Conn) {
	defer b.wg.Done()
	defer func() {
		b.mu.Lock()
		delete(b.conns, conn)
		b.mu.Unlock()
	}()
	defer conn.Close()
	defer func() { _ = recover() }() // a malformed request must never crash the client

	_ = conn.SetReadDeadline(time.Now().Add(requestReadTimeout))
	req, status, err := readHTTPRequest(bufio.NewReaderSize(conn, 32<<10))
	if err != nil {
		if status != 0 {
			writeJSONError(conn, status, err.Error())
		}
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(responseTimeout))

	// Block DNS rebinding (Host check) and cross-site requests (Origin check on state-changing requests).
	if !b.hostAllowed(req.Headers["host"]) {
		writeJSONError(conn, 403, "unexpected Host header")
		return
	}
	if req.Method == "POST" && !originAllowed(req.Headers["origin"], req.Headers["host"]) {
		writeJSONError(conn, 403, "cross-origin request refused")
		return
	}
	b.route(conn, req)
}

func (b *HTTPBridge) route(conn net.Conn, req *httpRequest) {
	switch req.Method + " " + req.Path {
	case "GET /", "GET /index.html":
		serveStatic(conn, "static/index.html", "text/html; charset=utf-8")
	case "GET /style.css":
		serveStatic(conn, "static/style.css", "text/css; charset=utf-8")
	case "GET /app.js":
		serveStatic(conn, "static/app.js", "text/javascript; charset=utf-8")
	case "GET /favicon.ico":
		writeResponse(conn, 204, "", nil)
	case "GET /events":
		b.serveEvents(conn)
	case "GET /api/state":
		writeJSON(conn, 200, b.ctrl.Snapshot())
	case "POST /api/login":
		b.handleLogin(conn, req)
	case "POST /api/chat":
		b.handleChat(conn, req)
	case "POST /api/file":
		b.handleFile(conn, req)
	case "GET /api/download":
		b.handleDownload(conn, req)
	case "POST /api/loss":
		b.handleLoss(conn, req)
	case "POST /api/logout":
		_ = b.ctrl.Logout()
		writeJSON(conn, 200, map[string]any{"ok": true})
	default:
		if req.Method != "GET" && req.Method != "POST" {
			writeJSONError(conn, 405, "method not allowed")
			return
		}
		writeJSONError(conn, 404, "not found")
	}
}

func (b *HTTPBridge) handleLogin(conn net.Conn, req *httpRequest) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		writeJSONError(conn, 400, "request body must be JSON with username and password")
		return
	}
	if err := b.ctrl.ConnectAndLogin(in.Username, in.Password); err != nil {
		writeJSONError(conn, 400, err.Error())
		return
	}
	writeJSON(conn, 200, map[string]any{"ok": true, "user_id": b.ctrl.UserID(), "username": b.ctrl.Username()})
}

func (b *HTTPBridge) handleChat(conn net.Conn, req *httpRequest) {
	var in struct {
		TargetID uint16 `json:"target_id"`
		Text     string `json:"text"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		writeJSONError(conn, 400, "request body must be JSON with target_id and text")
		return
	}
	if in.TargetID == protocol.ServerID {
		in.TargetID = protocol.BroadcastTarget // 0 and 65535 both mean "everyone"
	}
	if err := b.ctrl.SendChat(in.TargetID, in.Text); err != nil {
		writeJSONError(conn, 400, err.Error())
		return
	}
	writeJSON(conn, 200, map[string]any{"ok": true})
}

func (b *HTTPBridge) handleFile(conn net.Conn, req *httpRequest) {
	var in struct {
		TargetID   uint16 `json:"target_id"`
		Filename   string `json:"filename"`
		Base64Data string `json:"base64_data"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		writeJSONError(conn, 400, "request body must be JSON with target_id, filename and base64_data")
		return
	}
	data, err := base64.StdEncoding.DecodeString(in.Base64Data)
	if err != nil {
		writeJSONError(conn, 400, "base64_data is not valid base64")
		return
	}
	stream, err := b.ctrl.SendFile(in.TargetID, in.Filename, data)
	if err != nil {
		writeJSONError(conn, 400, err.Error())
		return
	}
	writeJSON(conn, 200, map[string]any{"ok": true, "stream_id": stream})
}

// handleDownload serves GET /api/download?name=<file>[&inline=1] from the download dir; only pictures go inline.
func (b *HTTPBridge) handleDownload(conn net.Conn, req *httpRequest) {
	q, err := url.ParseQuery(req.Query)
	if err != nil {
		writeJSONError(conn, 400, "malformed query string")
		return
	}
	name := filepath.Base(q.Get("name"))
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		writeJSONError(conn, 404, "file not found")
		return
	}
	data, err := os.ReadFile(filepath.Join(b.ctrl.DownloadDir(), name))
	if err != nil {
		writeJSONError(conn, 404, "file not found")
		return
	}
	contentType, isImage := imageTypes[strings.ToLower(filepath.Ext(name))]
	if !isImage {
		contentType = "application/octet-stream"
	}
	disposition := "attachment"
	if isImage && q.Get("inline") == "1" {
		disposition = "inline"
	}
	writeResponseWith(conn, 200, contentType, data, []string{
		"Content-Disposition: " + contentDisposition(disposition, name),
		"Content-Security-Policy: sandbox",
	})
}

// handleLoss sets the simulated outgoing packet loss of this client (demo slider).
func (b *HTTPBridge) handleLoss(conn net.Conn, req *httpRequest) {
	var in struct {
		Rate float64 `json:"rate"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		writeJSONError(conn, 400, "request body must be JSON with rate")
		return
	}
	if in.Rate < 0 || in.Rate > maxSimulatedLoss {
		writeJSONError(conn, 400, "rate must be between 0 and 0.95")
		return
	}
	b.ctrl.SetDropRate(in.Rate)
	writeJSON(conn, 200, map[string]any{"ok": true, "rate": in.Rate})
}

// serveEvents streams controller events as SSE ("data: <json>" lines) until the browser or bridge closes.
func (b *HTTPBridge) serveEvents(conn net.Conn) {
	head := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/event-stream; charset=utf-8\r\n" +
		"Cache-Control: no-store\r\n" +
		"Connection: keep-alive\r\n" +
		"X-Content-Type-Options: nosniff\r\n\r\n"
	if _, err := io.WriteString(conn, head); err != nil {
		return
	}
	events := b.ctrl.SubscribeEvents()
	defer b.ctrl.UnsubscribeEvents(events)

	// The browser never writes on this connection, so a returning read means the tab closed or reloaded.
	gone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		close(gone)
	}()

	w := bufio.NewWriter(conn)
	write := func(s string) bool {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := w.WriteString(s); err != nil {
			return false
		}
		return w.Flush() == nil
	}
	if !write("retry: 2000\n\n") {
		return
	}
	keepAlive := time.NewTicker(sseKeepAlive)
	defer keepAlive.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-gone:
			return
		case <-keepAlive.C:
			if !write(": keep-alive\n\n") {
				return
			}
		case ev, ok := <-events:
			if !ok {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			if !write("data: " + string(data) + "\n\n") {
				return
			}
		}
	}
}

func (b *HTTPBridge) hostAllowed(host string) bool {
	if host == "" || !b.loopback {
		return true
	}
	return isLoopbackHost(stripPort(host))
}

// originAllowed accepts a missing Origin (curl, tests) or an Origin equal to this server.
func originAllowed(origin, host string) bool {
	if origin == "" {
		return true
	}
	rest, ok := strings.CutPrefix(origin, "http://")
	if !ok {
		return false
	}
	return strings.EqualFold(rest, host)
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// readHTTPRequest parses one request; on error it returns the status to answer with, or 0 to just close.
func readHTTPRequest(br *bufio.Reader) (*httpRequest, int, error) {
	line, err := readHTTPLine(br, maxRequestLineBytes)
	if err != nil {
		if errors.Is(err, errHeaderTooLarge) {
			return nil, 414, errors.New("request line too long")
		}
		return nil, 0, err
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") || !strings.HasPrefix(parts[1], "/") {
		return nil, 400, errMalformed
	}
	req := &httpRequest{Method: parts[0], Headers: make(map[string]string)}
	req.Path, req.Query, _ = strings.Cut(parts[1], "?")

	total := len(line)
	for i := 0; ; i++ {
		if i >= maxHeaderLines {
			return nil, 431, errHeaderTooLarge
		}
		h, err := readHTTPLine(br, maxHeaderBytes)
		if err != nil {
			if errors.Is(err, errHeaderTooLarge) {
				return nil, 431, err
			}
			return nil, 0, err
		}
		total += len(h)
		if total > maxHeaderBytes {
			return nil, 431, errHeaderTooLarge
		}
		if h == "" {
			break
		}
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return nil, 400, errMalformed
		}
		req.Headers[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
	}

	if req.Headers["transfer-encoding"] != "" {
		return nil, 501, errors.New("chunked request bodies are not supported; send Content-Length")
	}
	if cl := req.Headers["content-length"]; cl != "" {
		n, err := strconv.ParseInt(cl, 10, 64)
		if err != nil || n < 0 {
			return nil, 400, errors.New("invalid Content-Length")
		}
		if n > maxBodyBytes {
			return nil, 413, fmt.Errorf("request body larger than %d MiB", maxBodyBytes>>20)
		}
		req.Body = make([]byte, n)
		if _, err := io.ReadFull(br, req.Body); err != nil {
			return nil, 400, errors.New("request body shorter than Content-Length")
		}
	}
	return req, 0, nil
}

// readHTTPLine reads one CRLF- (or LF-) terminated line without the terminator.
func readHTTPLine(br *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return "", err
		}
		line = append(line, chunk...)
		if len(line) > limit {
			return "", errHeaderTooLarge
		}
		if !isPrefix {
			return string(line), nil
		}
	}
}

func serveStatic(conn net.Conn, name, contentType string) {
	body, err := staticFiles.ReadFile(name)
	if err != nil {
		writeJSONError(conn, 404, "not found")
		return
	}
	writeResponse(conn, 200, contentType, body)
}

func writeJSON(conn net.Conn, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeJSONError(conn, 500, "cannot encode response")
		return
	}
	writeResponse(conn, status, "application/json; charset=utf-8", body)
}

func writeJSONError(conn net.Conn, status int, msg string) {
	body, _ := json.Marshal(map[string]any{"ok": false, "error": msg})
	writeResponse(conn, status, "application/json; charset=utf-8", body)
}

func writeResponse(conn net.Conn, status int, contentType string, body []byte) {
	writeResponseWith(conn, status, contentType, body, nil)
}

// writeResponseWith writes a complete response; extra holds additional header lines without the trailing CRLF.
func writeResponseWith(conn net.Conn, status int, contentType string, body []byte, extra []string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", status, statusText(status))
	if contentType != "" {
		sb.WriteString("Content-Type: " + contentType + "\r\n")
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	sb.WriteString("Cache-Control: no-store\r\n")
	sb.WriteString("X-Content-Type-Options: nosniff\r\n")
	sb.WriteString("Content-Security-Policy: default-src 'self'; img-src 'self' data: blob:\r\n")
	for _, h := range extra {
		sb.WriteString(h + "\r\n")
	}
	sb.WriteString("Connection: close\r\n\r\n")
	w := bufio.NewWriter(conn)
	_, _ = w.WriteString(sb.String())
	_, _ = w.Write(body)
	_ = w.Flush()
}

// contentDisposition builds a Content-Disposition with an ASCII fallback and the RFC 5987 UTF-8 name.
func contentDisposition(kind, name string) string {
	safe := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	var enc strings.Builder
	for _, c := range []byte(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte("!#$&+-.^_`|~", c) >= 0:
			enc.WriteByte(c)
		default:
			fmt.Fprintf(&enc, "%%%02X", c)
		}
	}
	return kind + `; filename="` + safe + `"; filename*=UTF-8''` + enc.String()
}

func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 204:
		return "No Content"
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 413:
		return "Payload Too Large"
	case 414:
		return "URI Too Long"
	case 431:
		return "Request Header Fields Too Large"
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	}
	return "Status " + strconv.Itoa(code)
}
