package tests

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lancollab/internal/client"
)

// splitResponse separates the header block of a raw HTTP response from its body.
func splitResponse(t *testing.T, resp string) (head string, body []byte) {
	t.Helper()
	i := strings.Index(resp, "\r\n\r\n")
	if i < 0 {
		t.Fatalf("malformed response: %q", resp)
	}
	return resp[:i], []byte(resp[i+4:])
}

func TestHTTPBridgeDownloadServesImagesInlineAndFilesAsAttachments(t *testing.T) {
	dir := t.TempDir()
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0xAB}, 300)...)
	files := map[string][]byte{
		"photo.png":         png,
		"Holiday Photo.JPG": []byte("jpeg bytes"),
		"doc.pdf":           []byte("%PDF-1.4 not really"),
		"vector.svg":        []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"page.html":         []byte("<script>alert(1)</script>"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A file next to the download directory must never be reachable through the API.
	secret := "secret-" + filepath.Base(dir) + ".txt"
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), secret), []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctrl := client.NewController("127.0.0.1", 9000, 9001)
	ctrl.SetDownloadDir(dir)
	bridge, err := client.StartHTTPBridge("127.0.0.1:0", ctrl)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	addr := bridge.Addr()

	get := func(query, host string) (string, []byte) {
		resp := rawHTTP(t, addr, "GET /api/download?"+query+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
		return splitResponse(t, resp)
	}
	expect := func(what, head string, parts ...string) {
		t.Helper()
		for _, p := range parts {
			if !strings.Contains(head, p) {
				t.Fatalf("%s: header block does not contain %q:\n%s", what, p, head)
			}
		}
	}

	head, body := get("name=photo.png&inline=1", addr)
	expect("inline png", head, "200 OK", "Content-Type: image/png", "Content-Disposition: inline", "X-Content-Type-Options: nosniff")
	if !bytes.Equal(body, png) {
		t.Fatal("the picture must be served byte for byte")
	}

	head, _ = get("name=photo.png", addr)
	expect("png without inline", head, "Content-Type: image/png", "Content-Disposition: attachment")

	head, body = get("name=Holiday%20Photo.JPG&inline=1", addr)
	expect("jpeg with space and upper-case extension", head, "Content-Type: image/jpeg", "Content-Disposition: inline", `filename="Holiday Photo.JPG"`, "filename*=UTF-8''Holiday%20Photo.JPG")
	if string(body) != "jpeg bytes" {
		t.Fatalf("unexpected body %q", body)
	}

	// Only pictures go inline; everything else, especially SVG and HTML, must be a download.
	for _, name := range []string{"doc.pdf", "vector.svg", "page.html"} {
		head, _ = get("name="+name+"&inline=1", addr)
		expect(name+" with inline=1", head, "Content-Type: application/octet-stream", "Content-Disposition: attachment")
		if strings.Contains(head, "Content-Disposition: inline") || strings.Contains(head, "image/svg") {
			t.Fatalf("%s must not be displayed inline:\n%s", name, head)
		}
	}

	head, _ = get("name=missing.png", addr)
	expect("missing file", head, "404 Not Found")
	head, _ = get("name=..%2F"+secret, addr)
	expect("path traversal", head, "404 Not Found")
	head, _ = get("name=%2Fetc%2Fpasswd", addr)
	expect("absolute path", head, "404 Not Found")
	head, _ = get("name=", addr)
	expect("empty name", head, "404 Not Found")

	head, _ = get("name=photo.png&inline=1", "evil.example.com")
	expect("foreign Host header", head, "403 Forbidden")
}

func TestHTTPBridgeLossEndpointValidatesRate(t *testing.T) {
	ctrl := client.NewController("127.0.0.1", 9000, 9001)
	bridge, err := client.StartHTTPBridge("127.0.0.1:0", ctrl)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	addr := bridge.Addr()

	post := func(extraHeaders, body string) string {
		return rawHTTP(t, addr, "POST /api/loss HTTP/1.1\r\nHost: "+addr+"\r\n"+extraHeaders+
			"Content-Type: application/json\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	}

	if resp := post("", `{"rate":0.25}`); !strings.Contains(resp, "200 OK") {
		t.Fatalf("a valid rate must be accepted:\n%s", resp)
	}
	if got := ctrl.DropRate(); got != 0.25 {
		t.Fatalf("the controller drop rate is %v, want 0.25", got)
	}
	if got, _ := ctrl.Snapshot()["drop_rate"].(float64); got != 0.25 {
		t.Fatalf("the state snapshot reports drop_rate %v, want 0.25", got)
	}

	for _, body := range []string{`{"rate":1.5}`, `{"rate":-0.1}`, `{"rate":0.96}`, `{"rate":"lots"}`, `not json`} {
		if resp := post("", body); !strings.Contains(resp, "400 Bad Request") {
			t.Fatalf("%s must be refused:\n%s", body, resp)
		}
	}
	if resp := post("Origin: http://evil.example\r\n", `{"rate":0.9}`); !strings.Contains(resp, "403 Forbidden") {
		t.Fatalf("a foreign Origin must be refused:\n%s", resp)
	}
	if got := ctrl.DropRate(); got != 0.25 {
		t.Fatalf("refused requests must not change the rate, it is now %v", got)
	}
}
