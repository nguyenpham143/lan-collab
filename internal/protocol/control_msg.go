package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// PeerInfo describes one online user in AUTH_RES and PEER_UPDATE.
type PeerInfo struct {
	ID      uint16 `json:"id"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	UDPPort int    `json:"udp_port"`
}

// ControlMsg is the one JSON shape for all control messages; unused fields are omitted.
type ControlMsg struct {
	Type         string     `json:"type"`
	Version      int        `json:"version,omitempty"`
	UDPPort      int        `json:"udp_port,omitempty"`
	HeartbeatSec int        `json:"heartbeat_sec,omitempty"`
	Username     string     `json:"username,omitempty"`
	Password     string     `json:"password,omitempty"`
	OK           bool       `json:"ok,omitempty"`
	Reason       string     `json:"reason,omitempty"`
	UserID       uint16     `json:"user_id,omitempty"`
	SessionKey   []byte     `json:"session_key,omitempty"`
	Peers        []PeerInfo `json:"peers,omitempty"`
}

// ChatPayload is the plaintext JSON carried by CHAT_MSG on stream 1.
type ChatPayload struct {
	From string `json:"from"`
	Text string `json:"text"`
	TS   int64  `json:"ts"`
}

// FileDonePayload tells the sender (on stream 1) whether the received file matched its SHA-256.
type FileDonePayload struct {
	StreamID uint16 `json:"stream_id"`
	OK       bool   `json:"ok"`
	Reason   string `json:"reason,omitempty"`
}

// Framing errors.
var (
	ErrFrameTooLarge = errors.New("protocol: control frame exceeds maximum size")
	ErrEmptyFrame    = errors.New("protocol: empty control frame")
	ErrMissingType   = errors.New("protocol: control message has no type")
)

// WriteControlMsg writes a uint32 big-endian length plus JSON in one Write, so frames never interleave.
func WriteControlMsg(w io.Writer, msg ControlMsg) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("protocol: encode control message: %w", err)
	}
	if len(body) > MaxControlFrame {
		return ErrFrameTooLarge
	}

	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	_, err = w.Write(frame)
	return err
}

// ReadControlMsg reads one frame, checking the length before allocating so a forged prefix cannot exhaust memory.
func ReadControlMsg(r io.Reader) (ControlMsg, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return ControlMsg{}, err
	}

	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		return ControlMsg{}, ErrEmptyFrame
	}
	if n > MaxControlFrame {
		return ControlMsg{}, fmt.Errorf("%w (got %d)", ErrFrameTooLarge, n)
	}

	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return ControlMsg{}, err
	}

	var msg ControlMsg
	if err := json.Unmarshal(body, &msg); err != nil {
		return ControlMsg{}, fmt.Errorf("protocol: malformed control JSON: %w", err)
	}
	if msg.Type == "" {
		return ControlMsg{}, ErrMissingType
	}
	return msg, nil
}

// MarshalJSONCompact encodes v without HTML escaping, so '<' and '&' stay one byte each.
func MarshalJSONCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
