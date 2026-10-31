# LanCollab: Distributed, Streaming-based Client-Server Collaboration

LanCollab is a self-hosted chat and file-sharing application for a LAN. It runs on raw
sockets only: a TCP+TLS control channel for sign-in and presence, and a custom reliable
streaming protocol on UDP for chat and file transfer.

- **Language:** Go 1.22 or newer, standard library only (`go.mod` has no `require` block).
- **No high-level networking:** no `net/http`, no WebSocket library, no web framework. The
  browser UI is served by a small HTTP/1.1 server written on `net.Listener` and `bufio`.
- **Platforms:** Windows, macOS and Linux, on `localhost` or a local network.

## What it does

| Feature | How it works |
| --- | --- |
| Sign-in and presence | TCP+TLS on port 9000. `HELLO`, `AUTH_REQ`, `AUTH_RES`. A new username is registered on first sign-in. The server keeps each user's IP, ports and session key, and pushes `PEER_UPDATE` to everyone when someone joins or leaves. |
| Chat | Broadcast and direct messages over UDP port 9001, relayed by the server. Stream 1 is delivered in order and never waits for file data (no head-of-line blocking). |
| Reliable file transfer | Files are cut into 1024-byte chunks, sent on their own stream with Selective Repeat (individual ACKs), a dynamic RTT estimator, fast retransmit, flow control (`rwnd`) and CUBIC congestion control, and checked with SHA-256 at the receiver. |
| Resilience | Heartbeats every 3 s, a 10 s session timeout, per-client goroutines with `recover()`, socket errors handled without crashing the server. A transfer fails with a clear message when the other user leaves, and one slow recipient never delays other users' files. |
| Security | TLS on the control channel (optional certificate pinning). Every UDP payload is sealed with AES-256-GCM using a per-client session key; the header is authenticated as additional data. |
| User interface | Browser UI (HTML, CSS and vanilla JavaScript only) with online users, chat tabs, pictures and files shown inside the conversation, progress bars, a download link for received files and live link statistics. A console UI is also included. |

## 1. Install

1. Install Go 1.22 or newer from <https://go.dev/dl/>.
2. Check the installation:

   ```bash
   go version
   ```

   The output must show `go1.22` or higher.
3. Open a terminal in the `repo/` directory (the folder that contains `go.mod`).

There are no dependencies to download.

## 2. Build (optional)

You can run everything with `go run`. To build binaries instead:

```bash
# Linux / macOS
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client
go build -o bin/simtest ./cmd/simtest
```

```powershell
# Windows PowerShell
go build -o bin\server.exe ./cmd/server
go build -o bin\client.exe ./cmd/client
go build -o bin\simtest.exe ./cmd/simtest
```

## 3. Run the server

```bash
go run ./cmd/server
```

The server prints its addresses and the SHA-256 fingerprint of its TLS certificate:

```text
LanCollab server is running.
  control plane (TCP+TLS): [::]:9000
  data plane (UDP):        [::]:9001
  TLS fingerprint:         3f9c...
```

Stop it with `Ctrl+C`.

| Server flag | Default | Meaning |
| --- | --- | --- |
| `-tcp` | `0.0.0.0:9000` | Control-plane listen address |
| `-udp` | `0.0.0.0:9001` | Data-plane listen address |
| `-timeout` | `10s` | Remove a client after this long without UDP packets |
| `-loss` | `0` | Drop this fraction (0 to 1) of outgoing UDP datagrams, for demos |

## 4. Connect clients

### Browser UI (default)

```bash
go run ./cmd/client
```

1. The client prints a line such as `open http://127.0.0.1:8080 in your browser`.
2. Open that address in a browser.
3. Enter a username and password and press **Sign in**. A new username is registered with
   that password; a known username needs the same password.
4. Click a name in the **Online** list to open a direct conversation. Use the **Everyone**
   tab for broadcast chat.
5. In a direct conversation, send files in any of three ways: press the paperclip button
   (several files at once), drag files onto the conversation, or paste a screenshot with
   `Ctrl+V` (it is sent as `pasted-<timestamp>.png`). Each file is at most 64 MB. Files go
   to one person, so all three are disabled in the **Everyone** tab.
6. Pictures (PNG, JPEG, GIF, WebP, BMP) appear in the conversation as pictures: the sender
   sees the picture at once, dimmed with a thin progress bar until the receiver has
   verified it; the receiver sees a "Receiving photo" placeholder, then the picture. Click a
   picture to open it full size. Other files appear as cards with the file name, size,
   progress and, for received files, a **Download** link. The right panel also lists every
   transfer with its progress and the live link statistics.
7. Received files are saved in the `downloads/` directory, next to where you started the
   client. An existing file is never overwritten: `a.txt` becomes `a (1).txt`. If the other
   user signs out during a transfer, it is marked as failed (`bob went offline`). An
   incoming transfer that receives no data for 30 seconds is also failed
   (`no data received for 30s`), so a progress bar never stays stuck.

To run several clients on one machine, start the command again in another terminal. If port
8080 is busy, the client uses 8081, 8082 and so on, and prints the address.

### Console UI

```bash
go run ./cmd/client -ui console -user alice -pass secret
```

Type text to message everyone. Other commands:

| Command | Action |
| --- | --- |
| `/msg <id> <text>` | Direct message to user `<id>` |
| `/send <id> <path>` | Send a file to user `<id>` |
| `/peers` | List online users with their IDs |
| `/transfers` | List file transfers and their state |
| `/stats` | Show RTT, RTO, cwnd, receive window and retransmissions |
| `/help`, `/quit` | Help, sign out and exit |

### Client flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-server` | `127.0.0.1` | Server host name or IP |
| `-tcp`, `-udp` | `9000`, `9001` | Server ports |
| `-ui` | `http` | `http` (browser) or `console` |
| `-http` | `127.0.0.1:8080` | Address of the browser UI |
| `-user`, `-pass` | empty | Sign in automatically (browser UI) or skip the prompts (console UI) |
| `-pin` | empty | Expected TLS certificate fingerprint printed by the server |
| `-downloads` | `downloads` | Folder for received files |
| `-loss` | `0` | Drop this fraction of outgoing UDP datagrams, for demos |

## 5. Use it across a network

1. Start the server on one machine and find its LAN address (`ipconfig` on Windows,
   `ip addr` on Linux, `ifconfig` on macOS), for example `192.168.1.10`.
2. Allow **TCP 9000** and **UDP 9001** through that machine's firewall.
3. On every other machine run `go run ./cmd/client -server 192.168.1.10`.

The server certificate is self-signed and regenerated at every start, so by default the
channel is encrypted but the server is not authenticated. To close that gap, copy the
fingerprint the server printed and start clients with `-pin <fingerprint>`.

## 6. Test

Run everything from `repo/`:

```bash
gofmt -l .            # lists files that need formatting; fix them with: gofmt -w .
go vet ./...
go test -race ./...
```

On Windows, `-race` needs cgo and a C compiler (for example MinGW-w64). Without one, run
`go test ./...` instead.

The output of the final run is saved in `docs/test-results/go-test.txt` and
`docs/test-results/simtest.txt`.

Useful variations:

```bash
go test -v ./tests -run "TestControlFraming|TestUDPPacket|TestFileChunker"   # protocol
go test -v ./tests -run "TestRTT|TestCubic|TestRDT"                          # transport
go test -v ./tests -run "TestServer|TestAbrupt|TestHeartbeat|TestDuplicate"  # server resilience
go test -v ./tests -run "LeavesMidTransfer|TestPeerLeaving|TestRelayOverflow|TestSlowRecipient"  # failed transfers, slow recipients
go test -v ./tests -run "TestFileInitArriving|TestStalledIncoming|TestSlowButSteady"   # late FILE_INIT, inactivity timeout
go test -v ./tests -run "TestHTTPBridge"                                    # web bridge, downloads
go test -race -v ./tests -run "TestConcurrentTwentyClientsEndToEnd"          # 20 clients
go test -short ./...                                                         # skip the load test
```

### Network simulation with 20 clients and 10% packet loss

```bash
go run ./cmd/simtest -clients 20 -loss 0.10
```

The simulator starts a server and 20 concurrent clients in one process, drops 10% of all UDP
datagrams on every endpoint, makes every client broadcast a message and send a 20 KB file to
the next client, and prints a table with retransmission counts, RTT and cwnd per client. It
ends with `RESULT: PASS` or `RESULT: FAIL`.

In the browser UI, the **Simulated packet loss** slider (0 to 95%) makes this client drop
that fraction of its outgoing datagrams, which is a quick way to watch the retransmission
counter rise while files still arrive intact.

### Manual demonstration with several terminals

1. Terminal 1: `go run ./cmd/server -loss 0.1`
2. Terminals 2, 3 and 4: `go run ./cmd/client -ui console -user alice -pass a`, then `bob`
   and `carol` the same way.
3. In alice's terminal: `/peers`, then `/msg 2 hello bob`, then `/send 2 path/to/file`.
4. Watch the retransmission counter in `/stats` rise while the file still arrives intact.

## 7. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `cannot reach server 127.0.0.1:9000` | The server is not running, or a firewall blocks TCP 9000. |
| Sign-in works but chat or files never arrive | UDP 9001 is blocked. Allow it in the server's firewall. |
| `this user is already signed in from another client` | The name is online elsewhere. Sign out there first. |
| `wrong password for this username` | Accounts live in server memory and are lost when the server restarts. After a restart, any password registers the name again. |
| `tls: server certificate fingerprint does not match -pin` | The server restarted and generated a new certificate. Use the new fingerprint. |
| `address already in use` | Another program uses the port. Choose other ports with `-tcp` and `-udp` on the server and the client. |
| A transfer shows `<name> went offline` | The other user signed out or lost the connection during the transfer. Send the file again when they are back. |
| A transfer shows `no data received for 30s` | Nothing arrived for 30 seconds, usually because the sender's network dropped. Ask them to send it again. |
| Browser shows `unexpected Host header` | The UI only answers `localhost`, `127.0.0.1` and `[::1]`. Open `http://127.0.0.1:8080`. |

## 8. Project layout

```text
repo/
  cmd/server, cmd/client, cmd/simtest   entry points
  internal/protocol/                    wire formats, crypto, file chunking (no sockets)
  internal/transport/                   TCP+TLS control channel, RTT, CUBIC, Selective Repeat engine
  internal/server/                      sessions, hop-by-hop router, listeners
  internal/client/                      controller, console UI, HTTP bridge, static/ web UI
  tests/                                protocol, transport, resilience and 20-client tests
docs/design/system-design-v1.0.md       design and protocol specification
```

The three layers are kept apart on purpose: `protocol` and `transport` hold the network
logic, `client/controller.go`, `client/transfer.go` and `server/` hold the data processing, and the two UIs only
call the controller and render its events.

## 9. Rubric map

| Step | Where |
| --- | --- |
| 1. Protocol design | `docs/design/system-design-v1.0.md`, `internal/protocol/` |
| 2. Handshake | `server.handleConn`, `client.ConnectAndLogin` (`HELLO` / `HELLO_ACK`) |
| 3. Authentication and state | `internal/server/session_mgr.go` |
| 4. Concurrency | one goroutine per client, per-recipient forwarders, `go test -race` |
| 5. Streaming chat | `internal/server/router.go`, `internal/transport/rdt_udp.go` and `rdt_recv.go` |
| 6. Reliable file transfer | `internal/protocol/file_chunker.go`, `rdt_recv.go`, `client/transfer.go` |
| 7. Resilience | heartbeat sweeper, `recover()`, tests in `tests/concurrency_test.go` and `tests/transfer_failure_test.go` |
| 8. Security | `internal/protocol/crypto.go` |
| 9. Browser UI | `internal/client/http_bridge.go`, `internal/client/static/` |
| 10. Testing | `tests/`, `cmd/simtest` |

## 10. Known limits

- Accounts are kept in memory only, and passwords travel over TLS but are not stored with a
  slow password hash.
- A file is held in memory while it is sent or received, so transfers are limited to 64 MB.
- If the sender signs out right after uploading a file, a receiver that is still receiving
  it sees the transfer fail (`went offline`) even though the server may still hold some
  packets.
- There is no automatic reconnect: after a disconnect the UI shows `Offline` and you sign in
  again.
- By default the TLS certificate is not verified; use `-pin` on untrusted networks.
