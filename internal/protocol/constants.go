// Package protocol defines the wire formats (control framing, UDP header, crypto, file chunking) with no socket code.
package protocol

import "time"

// Wire identity of every UDP datagram.
const (
	Magic   uint16 = 0x4C43 // ASCII "LC"; datagrams without it are dropped immediately
	Version uint8  = 0x01

	HeaderSize    = 24 // fixed binary UDP header: 6 rows x 4 bytes
	HeaderAADSize = 22 // header bytes 0..21 are authenticated as AES-GCM additional data
)

// Size limits: a full datagram is at most 1076 bytes, below the 1500-byte MTU, so IP never fragments.
const (
	MaxChunkSize        = 1024                          // max plaintext bytes carried by one datagram
	NonceSize           = 12                            // AES-GCM nonce
	GCMTagSize          = 16                            // AES-GCM authentication tag
	CryptoOverhead      = NonceSize + GCMTagSize        // 28 bytes added by encryption
	MaxEncryptedPayload = MaxChunkSize + CryptoOverhead // 1052 bytes
	MaxDatagramSize     = HeaderSize + MaxEncryptedPayload
	MaxControlFrame     = 65536 // max JSON body of one TCP control frame
	SessionKeySize      = 32    // AES-256
)

// Stream IDs: each (SenderID, StreamID) is an independent ordered stream, so file loss never delays chat.
const (
	StreamHeartbeat uint16 = 0 // unreliable HEARTBEAT
	StreamChat      uint16 = 1 // reliable CHAT_MSG and FILE_DONE
	FirstFileStream uint16 = 2 // every new file transfer uses the next StreamID >= 2
)

// Node identifiers.
const (
	ServerID        uint16 = 0      // the relay server
	BroadcastTarget uint16 = 0xFFFF // target_id for "everyone in the room"
)

// UDP message types (header byte 3).
const (
	MsgHeartbeat uint8 = 0x10
	MsgChat      uint8 = 0x11
	MsgFileInit  uint8 = 0x20
	MsgFileChunk uint8 = 0x21
	MsgFileEnd   uint8 = 0x22
	MsgFileDone  uint8 = 0x23
	MsgPacketAck uint8 = 0x30
)

// UDP header flags (header byte 4, bitmask).
const (
	FlagACK     uint8 = 0x01 // packet is an acknowledgement
	FlagEOM     uint8 = 0x02 // end of message / end of file
	FlagBcast   uint8 = 0x04 // message was sent to everyone
	FlagRetrans uint8 = 0x08 // packet is a retransmission (excluded from RTT samples, Karn's rule)
)

// Control-plane message types (JSON "type" field on the TCP+TLS channel).
const (
	CtrlHello      = "HELLO"
	CtrlHelloAck   = "HELLO_ACK"
	CtrlAuthReq    = "AUTH_REQ"
	CtrlAuthRes    = "AUTH_RES"
	CtrlPeerUpdate = "PEER_UPDATE"
	CtrlLogout     = "LOGOUT"
	CtrlError      = "ERROR" // sent before closing a connection that broke the handshake rules
)

// Window and timer defaults.
const (
	InitialCwnd     = 4.0  // packets
	InitialSsthresh = 16.0 // packets
	MaxCwnd         = 64   // packets, upper bound of cwnd
	RecvWindow      = 64   // packets buffered per receive stream; rwnd is advertised in 0..64

	HeartbeatInterval = 3 * time.Second
	SessionTimeout    = 10 * time.Second

	InitialRTO = 200 * time.Millisecond
	MinRTO     = 50 * time.Millisecond
	MaxRTO     = 2000 * time.Millisecond
)

// Default server ports.
const (
	DefaultTCPPort = 9000
	DefaultUDPPort = 9001
)

// IsDataMsg reports whether t is sequenced, acknowledged and retransmitted by the Selective Repeat engine.
func IsDataMsg(t uint8) bool {
	switch t {
	case MsgChat, MsgFileInit, MsgFileChunk, MsgFileEnd, MsgFileDone:
		return true
	}
	return false
}

// InitialSeq returns a stream's first seq: 0 for file streams (FILE_INIT), 1 for the chat stream.
func InitialSeq(streamID uint16) uint32 {
	if streamID >= FirstFileStream {
		return 0
	}
	return 1
}

// MsgTypeName returns a human-readable name for logs.
func MsgTypeName(t uint8) string {
	switch t {
	case MsgHeartbeat:
		return "HEARTBEAT"
	case MsgChat:
		return "CHAT_MSG"
	case MsgFileInit:
		return "FILE_INIT"
	case MsgFileChunk:
		return "FILE_CHUNK"
	case MsgFileEnd:
		return "FILE_END"
	case MsgFileDone:
		return "FILE_DONE"
	case MsgPacketAck:
		return "PACKET_ACK"
	}
	return "UNKNOWN"
}
