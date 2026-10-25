package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// PeerInfo lưu thông tin một người dùng đang trực tuyến trong mạng.
type PeerInfo struct {
	ID      uint16 `json:"id"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	UDPPort int    `json:"udp_port"`
}

// ControlMsg là bản tin JSON trao đổi trên kênh điều khiển TCP/TLS (:9000).
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

// WriteControlMsg đóng gói bản tin JSON kèm 4 bytes độ dài (Big-Endian) ở đầu.
func WriteControlMsg(w io.Writer, msg ControlMsg) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal control msg: %w", err)
	}
	if len(payload) == 0 || len(payload) > MaxControlFrame {
		return fmt.Errorf("invalid control frame length: %d", len(payload))
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))

	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return nil
}

// ReadControlMsg đọc chính xác 4 bytes độ dài trước, kiểm tra giới hạn rồi đọc tiếp N bytes JSON.
func ReadControlMsg(r io.Reader) (ControlMsg, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return ControlMsg{}, err
	}

	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 || length > MaxControlFrame {
		return ControlMsg{}, errors.New("control frame length out of bounds")
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return ControlMsg{}, fmt.Errorf("read frame payload: %w", err)
	}

	var msg ControlMsg
	if err := json.Unmarshal(payload, &msg); err != nil {
		return ControlMsg{}, fmt.Errorf("unmarshal control msg: %w", err)
	}
	if msg.Type == "" {
		return ControlMsg{}, errors.New("missing control message type")
	}
	return msg, nil
}
