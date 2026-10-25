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
