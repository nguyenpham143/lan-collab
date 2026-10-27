package tests

import (
	"bytes"
	"testing"

	"lancollab/internal/protocol"
)

func TestControlFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	orig := protocol.ControlMsg{
		Type:    "HELLO",
		Version: 1,
		UDPPort: 51001,
	}

	if err := protocol.WriteControlMsg(&buf, orig); err != nil {
		t.Fatalf("WriteControlMsg failed: %v", err)
	}

	got, err := protocol.ReadControlMsg(&buf)
	if err != nil {
		t.Fatalf("ReadControlMsg failed: %v", err)
	}
	if got.Type != "HELLO" || got.Version != 1 || got.UDPPort != 51001 {
		t.Fatalf("expected %+v, got %+v", orig, got)
	}
}

func TestControlFramingRejectsOversized(t *testing.T) {
	// Giả lập 4 bytes đầu khai báo độ dài 131072 bytes (> giới hạn 65536 bytes)
	oversizedHeader := []byte{0x00, 0x02, 0x00, 0x00}
	_, err := protocol.ReadControlMsg(bytes.NewReader(oversizedHeader))
	if err == nil {
		t.Fatal("expected ReadControlMsg to reject frame larger than MaxControlFrame (65536)")
	}
}

func TestUDPPacketMarshalAndUnmarshal(t *testing.T) {
	pkt := &protocol.UDPPacket{
		Header: protocol.UDPHeader{
			Magic:    protocol.Magic,
			Version:  protocol.Version,
			MsgType:  protocol.MsgChat,
			Flags:    protocol.FlagEOM,
			Rwnd:     64,
			StreamID: protocol.StreamChat,
			SenderID: 1,
			TargetID: 2,
			SeqNum:   42,
			AckNum:   10,
		},
		Payload: []byte("hello-udp-stream"),
	}

	wire, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if len(wire) != protocol.HeaderSize+len(pkt.Payload) {
		t.Fatalf("expected wire length %d, got %d", protocol.HeaderSize+len(pkt.Payload), len(wire))
	}

	parsed, err := protocol.UnmarshalUDPPacket(wire)
	if err != nil {
		t.Fatalf("UnmarshalUDPPacket failed: %v", err)
	}
	if parsed.Header.StreamID != 1 || parsed.Header.SenderID != 1 || parsed.Header.TargetID != 2 || parsed.Header.SeqNum != 42 || parsed.Header.Rwnd != 64 {
		t.Fatalf("header mismatch: %+v", parsed.Header)
	}
	if !bytes.Equal(parsed.Payload, pkt.Payload) {
		t.Fatalf("payload mismatch: got %q, want %q", parsed.Payload, pkt.Payload)
	}
}

func TestUDPPacketRejectsCorruptedChecksumAndBadMagic(t *testing.T) {
	pkt := &protocol.UDPPacket{
		Header: protocol.UDPHeader{
			Magic:    protocol.Magic,
			Version:  protocol.Version,
			MsgType:  protocol.MsgFileChunk,
			Rwnd:     32,
			StreamID: 2,
			SenderID: 1,
			TargetID: 3,
			SeqNum:   7,
		},
		Payload: []byte("chunk-data-bytes"),
	}
	wire, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// 1. Lật 1 bit ở byte thứ 10 (trường TargetID) -> Checksum phải phát hiện lỗi
	corrupted := append([]byte(nil), wire...)
	corrupted[10] ^= 0x01
	if _, err := protocol.UnmarshalUDPPacket(corrupted); err == nil {
		t.Fatal("expected error when 1 bit is flipped in UDP packet")
	}

	// 2. Sai Magic ở 2 bytes đầu -> Phải bị từ chối ngay
	badMagic := append([]byte(nil), wire...)
	badMagic[0] = 0x00
	if _, err := protocol.UnmarshalUDPPacket(badMagic); err == nil {
		t.Fatal("expected error on invalid magic number")
	}
}

