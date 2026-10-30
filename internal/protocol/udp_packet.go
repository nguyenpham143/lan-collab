package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// UDPHeader is the fixed 24-byte data-plane header (big-endian):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|         magic (0x4C43)        |  version (8b) | msg_type (8b) |
//	|   flags (8b)  |   rwnd (8b)   |         stream_id (16b)       |
//	|        sender_id (16b)        |         target_id (16b)       |
//	|                         seq_num (32b)                         |
//	|                         ack_num (32b)                         |
//	|       payload_len (16b)       |          checksum (16b)       |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type UDPHeader struct {
	Magic      uint16
	Version    uint8
	MsgType    uint8
	Flags      uint8
	Rwnd       uint8
	StreamID   uint16
	SenderID   uint16
	TargetID   uint16
	SeqNum     uint32
	AckNum     uint32
	PayloadLen uint16
	Checksum   uint16
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

// normalized fills zero Magic and Version, so encryption (AAD) and Marshal see the same header.
func (h UDPHeader) normalized() UDPHeader {
	if h.Magic == 0 {
		h.Magic = Magic
	}
	if h.Version == 0 {
		h.Version = Version
	}
	return h
}

// AAD returns header bytes 0..21 as AAD, with payload_len zeroed (unknown before encryption).
func (h UDPHeader) AAD() []byte {
	n := h.normalized()
	n.PayloadLen = 0
	n.Checksum = 0
	var full [HeaderSize]byte
	encodeHeader(n, full[:])
	out := make([]byte, HeaderAADSize)
	copy(out, full[:HeaderAADSize])
	return out
}

// Marshal encodes header plus payload, setting payload_len and the CRC-16 over the whole datagram.
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

// UnmarshalUDPPacket checks size, magic, version, length, then CRC-16, and returns a copy of the payload.
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

// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF): catches all 1- and 2-bit errors and bursts up to 16 bits.
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
