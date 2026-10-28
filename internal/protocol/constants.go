package protocol

import "time"

// Wire identity and header geometry for every UDP datagram.
const (
	Magic   uint16 = 0x4C43 // ASCII "LC"; datagrams without this magic prefix are dropped
	Version uint8  = 0x01

	HeaderSize    = 24 // Fixed binary UDP header size in bytes (6 words x 4 bytes)
	HeaderAADSize = 22 // Bytes 0..21 are authenticated as AES-GCM Additional Authenticated Data
)

// Payload and frame size limits.
// A full UDP datagram is at most 24 (header) + 12 (nonce) + 1024 (chunk) + 16 (tag) = 1076 bytes,
// staying well below the 1500-byte Ethernet MTU to avoid IP fragmentation.
const (
	MaxChunkSize        = 1024                          // Max plaintext bytes per UDP datagram
	NonceSize           = 12                            // AES-GCM standard 96-bit nonce
	GCMTagSize          = 16                            // AES-GCM 128-bit authentication tag
	CryptoOverhead      = NonceSize + GCMTagSize        // 28 bytes added by AES-GCM encryption
	MaxEncryptedPayload = MaxChunkSize + CryptoOverhead // 1052 bytes max ciphertext per datagram
	MaxDatagramSize     = HeaderSize + MaxEncryptedPayload
	MaxControlFrame     = 65536 // Max JSON payload size (64 KiB) for a TCP control frame
	SessionKeySize      = 32    // 256-bit symmetric session key for AES-256-GCM
)

// Stream multiplexing identifiers.
// Each (SenderID, StreamID) pair forms an independent ordered stream so that lost
// file chunks never block chat messages (preventing head-of-line blocking).
const (
	StreamHeartbeat uint16 = 0 // Unreliable keep-alive stream (HEARTBEAT)
	StreamChat      uint16 = 1 // Reliable control/chat stream (CHAT_MSG, FILE_DONE)
	FirstFileStream uint16 = 2 // File transfers allocate sequential StreamIDs >= 2
)

// Reserved node identifiers.
const (
	ServerID        uint16 = 0      // Central relay server ID
	BroadcastTarget uint16 = 0xFFFF // TargetID addressing all authenticated peers in the room
)

// UDP data-plane message types (Header byte 3).
const (
	MsgHeartbeat uint8 = 0x10
	MsgChat      uint8 = 0x11
	MsgFileInit  uint8 = 0x20
	MsgFileChunk uint8 = 0x21
	MsgFileEnd   uint8 = 0x22
	MsgFileDone  uint8 = 0x23
	MsgPacketAck uint8 = 0x30
)

// UDP header bitmask flags (Header byte 4).
const (
	FlagACK     uint8 = 0x01 // Packet carries a valid AckNum
	FlagEOM     uint8 = 0x02 // End of message or end of file stream
	FlagBcast   uint8 = 0x04 // Broadcast message to all peers
	FlagRetrans uint8 = 0x08 // Retransmitted packet (excluded from RTT sampling per Karn's rule)
)

// TCP+TLS control-plane JSON message types.
const (
	CtrlHello      = "HELLO"
	CtrlHelloAck   = "HELLO_ACK"
	CtrlAuthReq    = "AUTH_REQ"
	CtrlAuthRes    = "AUTH_RES"
	CtrlPeerUpdate = "PEER_UPDATE"
	CtrlLogout     = "LOGOUT"
	CtrlError      = "ERROR" // Sent prior to closing a connection that violates handshake rules
)

// Flow control, congestion control, and timer defaults.
const (
	InitialCwnd     = 4.0  // Initial congestion window (in packets)
	InitialSsthresh = 16.0 // Initial slow-start threshold (in packets)
	MaxWindow       = 64   // Upper bound for cwnd (in packets)
	MaxRecvBuffer   = 64   // Max out-of-order packets buffered per stream (rwnd in 0..64)

	HeartbeatInterval = 3 * time.Second
	SessionTimeout    = 10 * time.Second

	InitialRTO = 200 * time.Millisecond
	MinRTO     = 50 * time.Millisecond
	MaxRTO     = 2000 * time.Millisecond
)

// Default listening ports.
const (
	DefaultTCPPort = 9000
	DefaultUDPPort = 9001
)

// IsDataMsg reports whether t is a reliable data message that requires sequencing,
// acknowledgement, and Selective Repeat retransmission.
func IsDataMsg(t uint8) bool {
	switch t {
	case MsgChat, MsgFileInit, MsgFileChunk, MsgFileEnd, MsgFileDone:
		return true
	default:
		return false
	}
}

// InitialSeq returns the starting sequence number for streamID.
// File streams start at 0 (FILE_INIT = 0, chunks = 1..N, FILE_END = N+1), whereas the chat stream starts at 1.
func InitialSeq(streamID uint16) uint32 {
	if streamID >= FirstFileStream {
		return 0
	}
	return 1
}

// MsgTypeName returns the human-readable mnemonic for a UDP message type.
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
	default:
		return "UNKNOWN"
	}
}
