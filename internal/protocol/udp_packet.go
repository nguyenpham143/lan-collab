package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// UDPHeader biểu diễn đúng 24 bytes Header cố định của gói tin UDP (Big-Endian).
type UDPHeader struct {
	Magic      uint16 // Bytes 0-1:   0x4C43 ("LC")
	Version    uint8  // Byte 2:      0x01
	MsgType    uint8  // Byte 3:      Loại bản tin UDP
	Flags      uint8  // Byte 4:      Bitmask (ACK, EOM, BCAST, RETRANS)
	Rwnd       uint8  // Byte 5:      Cửa sổ nhận còn trống (Flow Control)
	StreamID   uint16 // Bytes 6-7:   0 = Heartbeat, 1 = Chat, 2+ = File
	SenderID   uint16 // Bytes 8-9:   ID người gửi
	TargetID   uint16 // Bytes 10-11: ID người nhận (0 = Server, 0xFFFF = Broadcast)
	SeqNum     uint32 // Bytes 12-15: Số thứ tự gói tin
	AckNum     uint32 // Bytes 16-19: Số thứ tự xác nhận (Individual ACK)
	PayloadLen uint16 // Bytes 20-21: Độ dài phần Payload theo sau
	Checksum   uint16 // Bytes 22-23: Mã kiểm tra lỗi bit CRC-16
}

// UDPPacket gồm 24-byte Header và mảng byte Payload đi kèm.
type UDPPacket struct {
	Header  UDPHeader
	Payload []byte
}

// Packet validation errors
var (
	ErrShortPacket     = errors.New("protocol: datagram shorter than the 24-byte header")
	ErrBadMagic        = errors.New("protocol: bad magic number")
	ErrBadVersion      = errors.New("protocol: unsupported protocol version")
	ErrLengthMismatch  = errors.New("protocol: payload_len does not match datagram size")
	ErrBadChecksum     = errors.New("protocol: CRC-16 checksum mismatch")
	ErrPayloadTooLarge = errors.New("protocol: payload exceeds the maximum size")
)

// Normalized fills Magic and Version when the caller left them zero
func (h UDPHeader) normalized() UDPHeader {
	if h.Magic == 0 {
		h.Magic = Magic
	}
	if h.Version == 0 {
		h.Version = Version
	}
	return h
}

// MarshalHeaderPrefix22 đóng gói 22 bytes đầu của Header (chưa gồm 2 bytes Checksum ở cuối).
func (h UDPHeader) MarshalHeaderPrefix22() []byte {
	n := h.normalized()
	n.PayloadLen = 0
	n.Checksum = 0
	var full [HeaderSize]byte
	encodeHeader(n, full[:])
	out := make([]byte, HeaderAADSize)
	copy(out, full[:HeaderAADSize])
	return out
}

// Marshal đóng gói toàn bộ UDPPacket thành mảng byte (24 bytes Header + Payload) kèm tính Checksum.
func (p *UDPPacket) Marshal() ([]byte, error) {
	if len(p.Payload) > MaxEncryptedPayload {
		return nil, fmt.Errorf("%w: %d bytes", ErrPayloadTooLarge, len(p.Payload))
	}
	h := p.Header.normalized()
	h.PayloadLen = uint16(len(p.Payload))
	h.Checksum = 0

	wire := make([]byte, HeaderSize+len(p.Payload))
	encodeHeader(h, wire)
	copy(wire[HeaderSize:], p.Payload)

	h.Checksum = ComputeCRC16(wire)
	binary.BigEndian.PutUint16(wire[22:24], h.Checksum)
	p.Header = h
	return wire, nil
}

// UnmarshalUDPPacket giải mã mảng byte nhận từ UDP Socket và kiểm tra tính hợp lệ + Checksum.
func UnmarshalUDPPacket(raw []byte) (*UDPPacket, error) {
	if len(raw) < HeaderSize {
		return nil, ErrShortPacket
	}
	h := decodeHeader(raw)
	if h.Magic != Magic {
		return nil, ErrBadMagic
	}
	if h.Version != Version {
		return nil, ErrBadVersion
	}
	if int(h.PayloadLen) != len(raw)-HeaderSize {
		return nil, ErrLengthMismatch
	}
	if int(h.PayloadLen) > MaxEncryptedPayload {
		return nil, ErrPayloadTooLarge
	}

	crc := crc16Update(0xFFFF, raw[:22])
	crc = crc16Update(crc, []byte{0, 0})
	crc = crc16Update(crc, raw[HeaderSize:])
	if crc != h.Checksum {
		return nil, ErrBadChecksum
	}
	payload := make([]byte, len(raw)-HeaderSize)
	copy(payload, raw[HeaderSize:])
	return &UDPPacket{Header: h, Payload: payload}, nil
}

func encodeHeader(h UDPHeader, out []byte) {
	binary.BigEndian.PutUint16(out[0:2], h.Magic)
	out[2] = h.Version
	out[3] = h.MsgType
	out[4] = h.Flags
	out[5] = h.Rwnd
	binary.BigEndian.PutUint16(out[6:8], h.StreamID)
	binary.BigEndian.PutUint16(out[8:10], h.SenderID)
	binary.BigEndian.PutUint16(out[10:12], h.TargetID)
	binary.BigEndian.PutUint32(out[12:16], h.SeqNum)
	binary.BigEndian.PutUint32(out[16:20], h.AckNum)
	binary.BigEndian.PutUint16(out[20:22], h.PayloadLen)
	binary.BigEndian.PutUint16(out[22:24], h.Checksum)
}

func decodeHeader(b []byte) UDPHeader {
	return UDPHeader{
		Magic:      binary.BigEndian.Uint16(b[0:2]),
		Version:    b[2],
		MsgType:    b[3],
		Flags:      b[4],
		Rwnd:       b[5],
		StreamID:   binary.BigEndian.Uint16(b[6:8]),
		SenderID:   binary.BigEndian.Uint16(b[8:10]),
		TargetID:   binary.BigEndian.Uint16(b[10:12]),
		SeqNum:     binary.BigEndian.Uint32(b[12:16]),
		AckNum:     binary.BigEndian.Uint32(b[16:20]),
		PayloadLen: binary.BigEndian.Uint16(b[20:22]),
		Checksum:   binary.BigEndian.Uint16(b[22:24]),
	}
}

var crc16Table = func() [256]uint16 {
	var t [256]uint16
	for i := 0; i < 256; i++ {
		crc := uint16(i) << 8
		for bit := 0; bit < 8; bit++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
		t[i] = crc
	}
	return t
}()

func crc16Update(crc uint16, data []byte) uint16 {
	for _, b := range data {
		crc = (crc << 8) ^ crc16Table[byte(crc>>8)^b]
	}
	return crc
}

// ComputeCRC16 returns the CRC-16/CCITT-FALSE of data.
func ComputeCRC16(data []byte) uint16 {
	return crc16Update(0xFFFF, data)
}
