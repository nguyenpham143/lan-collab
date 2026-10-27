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

// MarshalHeaderPrefix22 đóng gói 22 bytes đầu của Header (chưa gồm 2 bytes Checksum ở cuối).
func (h *UDPHeader) MarshalHeaderPrefix22() []byte {
	var buf [22]byte
	magic := h.Magic
	if magic == 0 {
		magic = Magic
	}
	ver := h.Version
	if ver == 0 {
		ver = Version
	}

	binary.BigEndian.PutUint16(buf[0:2], magic)
	buf[2] = ver
	buf[3] = h.MsgType
	buf[4] = h.Flags
	buf[5] = h.Rwnd
	binary.BigEndian.PutUint16(buf[6:8], h.StreamID)
	binary.BigEndian.PutUint16(buf[8:10], h.SenderID)
	binary.BigEndian.PutUint16(buf[10:12], h.TargetID)
	binary.BigEndian.PutUint32(buf[12:16], h.SeqNum)
	binary.BigEndian.PutUint32(buf[16:20], h.AckNum)
	binary.BigEndian.PutUint16(buf[20:22], h.PayloadLen)
	return buf[:]
}

// Marshal đóng gói toàn bộ UDPPacket thành mảng byte (24 bytes Header + Payload) kèm tính Checksum.
func (p *UDPPacket) Marshal() ([]byte, error) {
	if len(p.Payload) > 65535 {
		return nil, fmt.Errorf("udp payload too large: %d", len(p.Payload))
	}

	p.Header.PayloadLen = uint16(len(p.Payload))
	prefix22 := p.Header.MarshalHeaderPrefix22()

	wire := make([]byte, HeaderSize+len(p.Payload))
	copy(wire[0:22], prefix22)
	// Bytes 22..23 tạm thời bằng 0 trong lúc tính Checksum
	copy(wire[HeaderSize:], p.Payload)

	p.Header.Checksum = ComputeCRC16(wire)
	binary.BigEndian.PutUint16(wire[22:24], p.Header.Checksum)
	return wire, nil
}

// UnmarshalUDPPacket giải mã mảng byte nhận từ UDP Socket và kiểm tra tính hợp lệ + Checksum.
func UnmarshalUDPPacket(raw []byte) (*UDPPacket, error) {
	if len(raw) < HeaderSize {
		return nil, errors.New("udp packet shorter than 24-byte header")
	}

	hdr := UDPHeader{
		Magic:      binary.BigEndian.Uint16(raw[0:2]),
		Version:    raw[2],
		MsgType:    raw[3],
		Flags:      raw[4],
		Rwnd:       raw[5],
		StreamID:   binary.BigEndian.Uint16(raw[6:8]),
		SenderID:   binary.BigEndian.Uint16(raw[8:10]),
		TargetID:   binary.BigEndian.Uint16(raw[10:12]),
		SeqNum:     binary.BigEndian.Uint32(raw[12:16]),
		AckNum:     binary.BigEndian.Uint32(raw[16:20]),
		PayloadLen: binary.BigEndian.Uint16(raw[20:22]),
		Checksum:   binary.BigEndian.Uint16(raw[22:24]),
	}

	if hdr.Magic != Magic {
		return nil, fmt.Errorf("invalid magic: 0x%04X", hdr.Magic)
	}
	if hdr.Version != Version {
		return nil, fmt.Errorf("unsupported version: %d", hdr.Version)
	}
	if int(hdr.PayloadLen) != len(raw)-HeaderSize {
		return nil, fmt.Errorf("payload length mismatch: header=%d actual=%d", hdr.PayloadLen, len(raw)-HeaderSize)
	}

	// Tính lại Checksum với 2 bytes [22:24] đặt về 0 để đối chiếu
	checkBuf := make([]byte, len(raw))
	copy(checkBuf, raw)
	checkBuf[22] = 0
	checkBuf[23] = 0
	expectedCRC := ComputeCRC16(checkBuf)
	if hdr.Checksum != expectedCRC {
		return nil, fmt.Errorf("checksum mismatch: got 0x%04X, expected 0x%04X", hdr.Checksum, expectedCRC)
	}

	payload := make([]byte, hdr.PayloadLen)
	copy(payload, raw[HeaderSize:])

	return &UDPPacket{
		Header:  hdr,
		Payload: payload,
	}, nil
}

// ComputeCRC16 tính mã kiểm tra lỗi 16-bit (CRC-16-CCITT, đa thức 0x1021) phát hiện lỗi lật bit.
func ComputeCRC16(data []byte) uint16 {
	var crc uint16 = 0xFFFF
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if (crc & 0x8000) != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
