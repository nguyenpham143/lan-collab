package tests

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"strings"
	"testing"

	"lancollab/internal/protocol"
)

// ---------------------------------------------------------------------------
// 1. Control Framing Tests (TCP Length-Prefixed JSON)
// ---------------------------------------------------------------------------

func TestControlFraming(t *testing.T) {
	t.Run("single frame round-trip", func(t *testing.T) {
		var buf bytes.Buffer
		orig := protocol.ControlMsg{Type: "HELLO", Version: 1, UDPPort: 51001}
		if err := protocol.WriteControlMsg(&buf, orig); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		got, err := protocol.ReadControlMsg(&buf)
		if err != nil || got.Type != "HELLO" || got.Version != 1 || got.UDPPort != 51001 {
			t.Fatalf("unexpected msg: %+v, err=%v", got, err)
		}
	})

	t.Run("multiple sequential frames in one stream", func(t *testing.T) {
		var buf bytes.Buffer
		types := []string{"A", "B", "C"}
		for _, typ := range types {
			if err := protocol.WriteControlMsg(&buf, protocol.ControlMsg{Type: typ}); err != nil {
				t.Fatal(err)
			}
		}
		for _, typ := range types {
			got, err := protocol.ReadControlMsg(&buf)
			if err != nil || got.Type != typ {
				t.Fatalf("expected frame %q, got %+v err=%v", typ, got, err)
			}
		}
	})

	t.Run("boundary limits on read and write", func(t *testing.T) {
		// Exactly 65536 bytes is inside the limit: passes length check, fails on missing body.
		_, err := protocol.ReadControlMsg(bytes.NewReader([]byte{0x00, 0x01, 0x00, 0x00}))
		if err == nil || errors.Is(err, protocol.ErrFrameTooLarge) {
			t.Fatalf("a 65536-byte frame is allowed by the limit, got %v", err)
		}

		// Writer refuses to produce an oversized frame (> 65536 bytes).
		huge := protocol.ControlMsg{Type: "X", Username: strings.Repeat("a", 70000)}
		if err := protocol.WriteControlMsg(io.Discard, huge); !errors.Is(err, protocol.ErrFrameTooLarge) {
			t.Fatalf("expected ErrFrameTooLarge from writer, got %v", err)
		}
	})

	t.Run("rejects malformed and oversized frames", func(t *testing.T) {
		frame := func(body string) []byte {
			b := make([]byte, 4+len(body))
			binary.BigEndian.PutUint32(b, uint32(len(body)))
			copy(b[4:], body)
			return b
		}
		cases := []struct {
			name string
			wire []byte
			want error // nil means "any non-nil error"
		}{
			{"length one over limit (65537B)", []byte{0x00, 0x01, 0x00, 0x01}, protocol.ErrFrameTooLarge},
			{"length 128 KiB (131072B)", []byte{0x00, 0x02, 0x00, 0x00}, protocol.ErrFrameTooLarge},
			{"length 4 GiB", []byte{0xFF, 0xFF, 0xFF, 0xFF}, protocol.ErrFrameTooLarge},
			{"zero length", []byte{0, 0, 0, 0}, protocol.ErrEmptyFrame},
			{"invalid JSON", frame("{not json"), nil},
			{"JSON without type", frame(`{"version":1}`), protocol.ErrMissingType},
			{"truncated body", append([]byte{0, 0, 0, 10}, 'a', 'b', 'c'), nil},
			{"empty input", nil, nil},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := protocol.ReadControlMsg(bytes.NewReader(tc.wire))
				if err == nil {
					t.Fatal("expected an error")
				}
				if tc.want != nil && !errors.Is(err, tc.want) {
					t.Fatalf("got %v, want %v", err, tc.want)
				}
			})
		}
	})
}

// ---------------------------------------------------------------------------
// 2. UDP Wire Codec & CRC-16 Checksum Tests
// ---------------------------------------------------------------------------

func TestUDPPacketAndCRC16(t *testing.T) {
	t.Run("CRC-16/CCITT-FALSE standard reference vector", func(t *testing.T) {
		if got := protocol.ComputeCRC16([]byte("123456789")); got != 0x29B1 {
			t.Fatalf("CRC-16/CCITT-FALSE of \"123456789\" = %#04x, want 0x29b1", got)
		}
	})

	t.Run("marshal, unmarshal, magic validation, and header bit flip", func(t *testing.T) {
		hdr := protocol.UDPHeader{
			Magic:    protocol.Magic,
			Version:  protocol.Version,
			MsgType:  protocol.MsgChat,
			Flags:    protocol.FlagEOM,
			Rwnd:     64,
			StreamID: protocol.StreamChat,
			SenderID: 1,
			TargetID: 2,
			SeqNum:   42,
		}
		pkt := &protocol.UDPPacket{Header: hdr, Payload: []byte("hello-udp-stream")}
		wire, err := pkt.Marshal()
		if err != nil || len(wire) != protocol.HeaderSize+len(pkt.Payload) {
			t.Fatalf("marshal failed: len=%d err=%v", len(wire), err)
		}

		parsed, err := protocol.UnmarshalUDPPacket(wire)
		if err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if !bytes.Equal(parsed.Payload, pkt.Payload) || parsed.Header.SeqNum != 42 {
			t.Fatalf("mismatch after unmarshal: %+v", parsed)
		}

		// Flip 1 bit in wire byte 10 (TargetID) -> Checksum must reject
		corrupt := append([]byte(nil), wire...)
		corrupt[10] ^= 0x01
		if _, err := protocol.UnmarshalUDPPacket(corrupt); !errors.Is(err, protocol.ErrBadChecksum) {
			t.Fatalf("expected ErrBadChecksum on corrupted bit, got %v", err)
		}

		// Invalid Magic in the first 2 bytes -> Must reject immediately
		badMagic := append([]byte(nil), wire...)
		badMagic[0] = 0x00
		if _, err := protocol.UnmarshalUDPPacket(badMagic); !errors.Is(err, protocol.ErrBadMagic) {
			t.Fatalf("expected ErrBadMagic on invalid magic, got %v", err)
		}
	})

	t.Run("exhaustive single-bit flip rejection across entire datagram", func(t *testing.T) {
		key, err := protocol.GenerateSessionKey()
		if err != nil {
			t.Fatal(err)
		}
		hdr := protocol.UDPHeader{MsgType: protocol.MsgFileChunk, Rwnd: 64, StreamID: 2, SenderID: 7, TargetID: 9, SeqNum: 1234}
		enc, err := protocol.EncryptPayload(key, hdr.MarshalHeaderPrefix22(), bytes.Repeat([]byte{0xAB}, 300))
		if err != nil {
			t.Fatal(err)
		}
		pkt := &protocol.UDPPacket{Header: hdr, Payload: enc}
		wire, err := pkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := protocol.UnmarshalUDPPacket(wire); err != nil {
			t.Fatalf("untouched datagram must parse: %v", err)
		}
		for byteIdx := range wire {
			for bit := 0; bit < 8; bit++ {
				mutated := append([]byte(nil), wire...)
				mutated[byteIdx] ^= 1 << bit
				if _, err := protocol.UnmarshalUDPPacket(mutated); err == nil {
					t.Fatalf("flipping bit %d of byte %d was not detected", bit, byteIdx)
				}
			}
		}
	})

	t.Run("MTU size bounds, short packets, and random garbage fuzzing", func(t *testing.T) {
		key, _ := protocol.GenerateSessionKey()
		hdr := protocol.UDPHeader{MsgType: protocol.MsgFileChunk, StreamID: 2, SenderID: 1, TargetID: 2, SeqNum: 1}
		h22 := hdr.MarshalHeaderPrefix22()

		enc, err := protocol.EncryptPayload(key, h22, bytes.Repeat([]byte{7}, protocol.MaxChunkSize))
		if err != nil {
			t.Fatal(err)
		}
		if len(enc) != 1052 {
			t.Fatalf("a full chunk must encrypt to 1052 bytes, got %d", len(enc))
		}
		pkt := &protocol.UDPPacket{Header: hdr, Payload: enc}
		wire, err := pkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) != 1076 {
			t.Fatalf("a full datagram must be 1076 bytes, got %d", len(wire))
		}

		tooBig := &protocol.UDPPacket{Header: hdr, Payload: make([]byte, protocol.MaxEncryptedPayload+1)}
		if _, err := tooBig.Marshal(); !errors.Is(err, protocol.ErrPayloadTooLarge) {
			t.Fatalf("an oversized payload must be refused by Marshal, got %v", err)
		}
		if _, err := protocol.UnmarshalUDPPacket(nil); !errors.Is(err, protocol.ErrShortPacket) {
			t.Fatalf("empty datagram: got %v", err)
		}
		if _, err := protocol.UnmarshalUDPPacket(wire[:23]); !errors.Is(err, protocol.ErrShortPacket) {
			t.Fatalf("23-byte datagram: got %v", err)
		}
		if _, err := protocol.UnmarshalUDPPacket(wire[:30]); !errors.Is(err, protocol.ErrLengthMismatch) {
			t.Fatalf("truncated datagram: got %v", err)
		}

		// Random garbage of every size must be rejected without panicking.
		rng := rand.New(rand.NewSource(1))
		for i := 0; i < 500; i++ {
			junk := make([]byte, rng.Intn(1200))
			for j := range junk {
				junk[j] = byte(rng.Intn(256))
			}
			_, _ = protocol.UnmarshalUDPPacket(junk)
		}
	})
}

// ---------------------------------------------------------------------------
// 3. AES-256-GCM Payload Encryption & Header AAD Authentication Tests
// ---------------------------------------------------------------------------

func TestAESGCMAuthentication(t *testing.T) {
	key, err := protocol.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _ := protocol.GenerateSessionKey()
	hdr := protocol.UDPHeader{MsgType: protocol.MsgChat, Flags: protocol.FlagEOM, StreamID: 1, SenderID: 1, TargetID: 2, SeqNum: 5}
	enc, err := protocol.EncryptPayload(key, hdr.MarshalHeaderPrefix22(), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	build := func(h protocol.UDPHeader, payload []byte) *protocol.UDPPacket {
		p := &protocol.UDPPacket{Header: h, Payload: payload}
		wire, err := p.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := protocol.UnmarshalUDPPacket(wire)
		if err != nil {
			t.Fatalf("re-checksummed datagram must parse: %v", err)
		}
		return parsed
	}

	t.Run("valid decryption and random nonce uniqueness", func(t *testing.T) {
		ok := build(hdr, enc)
		plain, err := protocol.DecryptPayload(key, ok.Header.MarshalHeaderPrefix22(), ok.Payload)
		if err != nil || string(plain) != "secret" {
			t.Fatalf("untouched packet must decrypt: plain=%q err=%v", plain, err)
		}

		enc2, _ := protocol.EncryptPayload(key, hdr.MarshalHeaderPrefix22(), []byte("secret"))
		if bytes.Equal(enc, enc2) {
			t.Fatal("two encryptions of the same plaintext must differ (random nonce)")
		}
	})

	t.Run("AAD rejects modified header fields even with valid CRC", func(t *testing.T) {
		redirected := hdr
		redirected.TargetID = 3
		p := build(redirected, enc)
		if _, err := protocol.DecryptPayload(key, p.Header.MarshalHeaderPrefix22(), p.Payload); !errors.Is(err, protocol.ErrDecrypt) {
			t.Fatalf("changed target_id must fail GCM authentication, got %v", err)
		}

		renumbered := hdr
		renumbered.SeqNum = 6
		p = build(renumbered, enc)
		if _, err := protocol.DecryptPayload(key, p.Header.MarshalHeaderPrefix22(), p.Payload); !errors.Is(err, protocol.ErrDecrypt) {
			t.Fatalf("changed seq_num must fail GCM authentication, got %v", err)
		}
	})

	t.Run("rejects tampered ciphertext", func(t *testing.T) {
		flipped := append([]byte(nil), enc...)
		flipped[len(flipped)-1] ^= 0x80
		p := build(hdr, flipped)
		if _, err := protocol.DecryptPayload(key, p.Header.MarshalHeaderPrefix22(), p.Payload); !errors.Is(err, protocol.ErrDecrypt) {
			t.Fatalf("changed ciphertext must fail GCM authentication, got %v", err)
		}
	})

	t.Run("rejects invalid keys, short ciphertexts, and oversized plaintexts", func(t *testing.T) {
		h22 := hdr.MarshalHeaderPrefix22()
		if _, err := protocol.DecryptPayload(otherKey, h22, enc); !errors.Is(err, protocol.ErrDecrypt) {
			t.Fatalf("wrong key must fail, got %v", err)
		}
		if _, err := protocol.EncryptPayload(key[:16], h22, []byte("x")); !errors.Is(err, protocol.ErrBadKeySize) {
			t.Fatalf("16-byte key must be refused, got %v", err)
		}
		if _, err := protocol.DecryptPayload(key, h22, make([]byte, 10)); !errors.Is(err, protocol.ErrCiphertextTooShort) {
			t.Fatalf("truncated ciphertext must be refused, got %v", err)
		}
		if _, err := protocol.EncryptPayload(key, h22, make([]byte, protocol.MaxChunkSize+1)); !errors.Is(err, protocol.ErrPayloadTooLarge) {
			t.Fatalf("1025-byte plaintext must be refused, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// 4. File Chunker & Reassembler Tests
// ---------------------------------------------------------------------------

func TestFileChunkerAndReassembler(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), 2500) // 3 chunks
	meta, chunks := protocol.SplitFileChunks(raw)

	t.Run("chunk splitting across boundary sizes", func(t *testing.T) {
		for _, size := range []int{1, 1023, 1024, 1025, 2048, 3000} {
			m, cs := protocol.SplitFileChunks(make([]byte, size))
			want := (size + 1023) / 1024
			if int(m.TotalChunks) != want || len(cs) != want {
				t.Fatalf("size %d: got %d chunks, want %d", size, len(cs), want)
			}
			total := 0
			for _, c := range cs {
				if len(c) > protocol.MaxChunkSize {
					t.Fatalf("size %d: chunk of %d bytes exceeds 1024", size, len(c))
				}
				total += len(c)
			}
			if total != size || m.Size != int64(size) {
				t.Fatalf("size %d: chunks add up to %d", size, total)
			}
		}
	})

	t.Run("out-of-order reassembly", func(t *testing.T) {
		data := []byte(strings.Repeat("ABCD1234", 300)) // 2400 bytes -> 3 chunks
		m, cs := protocol.SplitFileChunks(data)
		if m.TotalChunks != 3 {
			t.Fatalf("expected 3 chunks, got %d", m.TotalChunks)
		}
		r := protocol.NewFileReassembler()
		r.AddInit(7, 2, m)

		if _, _, done, err := r.AddChunk(7, 2, 3, cs[2]); err != nil || done {
			t.Fatalf("step 1 unexpected: done=%v err=%v", done, err)
		}
		if _, _, done, err := r.AddChunk(7, 2, 1, cs[0]); err != nil || done {
			t.Fatalf("step 2 unexpected: done=%v err=%v", done, err)
		}
		out, _, done, err := r.AddChunk(7, 2, 2, cs[1])
		if err != nil || !done || !bytes.Equal(out, data) {
			t.Fatalf("reassembly failed: done=%v err=%v", done, err)
		}
	})

	t.Run("empty file reassembly", func(t *testing.T) {
		emptyMeta, emptyChunks := protocol.SplitFileChunks(nil)
		if emptyMeta.TotalChunks != 1 || len(emptyChunks) != 1 {
			t.Fatalf("empty file must produce 1 empty chunk, got %d", emptyMeta.TotalChunks)
		}
		r := protocol.NewFileReassembler()
		r.AddInit(1, 2, emptyMeta)
		out, _, done, err := r.AddChunk(1, 2, 1, emptyChunks[0])
		if err != nil || !done || len(out) != 0 {
			t.Fatalf("empty file: done=%v len=%d err=%v", done, len(out), err)
		}
	})

	t.Run("concurrent transfers from different senders with same stream ID", func(t *testing.T) {
		rawB := bytes.Repeat([]byte("y"), 1500)
		metaB, chunksB := protocol.SplitFileChunks(rawB)
		r := protocol.NewFileReassembler()
		r.AddInit(1, 2, meta)
		r.AddInit(3, 2, metaB)
		var outA, outB []byte
		for i := 0; i < 3; i++ {
			if data, _, done, err := r.AddChunk(1, 2, uint32(i+1), chunks[i]); err != nil {
				t.Fatal(err)
			} else if done {
				outA = data
			}
			if i < 2 {
				if data, _, done, err := r.AddChunk(3, 2, uint32(i+1), chunksB[i]); err != nil {
					t.Fatal(err)
				} else if done {
					outB = data
				}
			}
		}
		if !bytes.Equal(outA, raw) || !bytes.Equal(outB, rawB) {
			t.Fatal("transfers from different senders were mixed up")
		}
	})

	t.Run("hash mismatch on corrupted chunk", func(t *testing.T) {
		r := protocol.NewFileReassembler()
		r.AddInit(1, 2, meta)
		bad := append([]byte(nil), chunks[1]...)
		bad[0] ^= 0x01
		if _, _, _, err := r.AddChunk(1, 2, 1, chunks[0]); err != nil {
			t.Fatalf("early chunk must be accepted: %v", err)
		}
		if _, _, _, err := r.AddChunk(1, 2, 2, bad); err != nil {
			t.Fatalf("corrupted chunk is only detected upon completion: %v", err)
		}
		_, _, done, err := r.AddChunk(1, 2, 3, chunks[2])
		if done || !errors.Is(err, protocol.ErrHashMismatch) {
			t.Fatalf("expected ErrHashMismatch, got done=%v err=%v", done, err)
		}
	})

	t.Run("chunk without init", func(t *testing.T) {
		r := protocol.NewFileReassembler()
		if _, _, _, err := r.AddChunk(1, 2, 1, chunks[0]); !errors.Is(err, protocol.ErrUnknownTransfer) {
			t.Fatalf("expected ErrUnknownTransfer, got %v", err)
		}
	})

	t.Run("inconsistent chunk count in metadata", func(t *testing.T) {
		wrong := meta
		wrong.TotalChunks = 99
		if err := wrong.Validate(); err == nil {
			t.Fatal("Validate must reject chunk count that does not match size")
		}
		r := protocol.NewFileReassembler()
		r.AddInit(1, 2, wrong)
		if _, _, _, err := r.AddChunk(1, 2, 1, chunks[0]); !errors.Is(err, protocol.ErrBadFileMeta) {
			t.Fatalf("expected ErrBadFileMeta, got %v", err)
		}
	})

	t.Run("sequence number out of range", func(t *testing.T) {
		r := protocol.NewFileReassembler()
		r.AddInit(1, 2, meta)
		for _, seq := range []uint32{0, 4, 99} {
			if _, _, _, err := r.AddChunk(1, 2, seq, chunks[0]); !errors.Is(err, protocol.ErrChunkOutOfRange) {
				t.Fatalf("seq %d: expected ErrChunkOutOfRange, got %v", seq, err)
			}
		}
	})

	t.Run("oversized chunk payload", func(t *testing.T) {
		r := protocol.NewFileReassembler()
		r.AddInit(1, 2, meta)
		if _, _, _, err := r.AddChunk(1, 2, 1, make([]byte, 1025)); !errors.Is(err, protocol.ErrChunkTooLarge) {
			t.Fatalf("expected ErrChunkTooLarge, got %v", err)
		}
	})
}
