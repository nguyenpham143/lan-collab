package protocol

const (
	// Magic ("LC" = 0x4C43) và phiên bản giao thức
	Magic   uint16 = 0x4C43
	Version uint8  = 0x01

	// Kích thước khung gói tin
	HeaderSize      = 24
	MaxChunkSize    = 1024
	MaxControlFrame = 65536

	// Định danh luồng (StreamID) chống Head-of-Line Blocking
	StreamHeartbeat uint16 = 0
	StreamChat      uint16 = 1

	// Địa chỉ đích đặc biệt
	ServerTarget    uint16 = 0
	BroadcastTarget uint16 = 0xFFFF

	// Mã loại bản tin UDP (msg_type)
	MsgHeartbeat uint8 = 0x10
	MsgChat      uint8 = 0x11
	MsgFileInit  uint8 = 0x20
	MsgFileChunk uint8 = 0x21
	MsgFileEnd   uint8 = 0x22
	MsgFileDone  uint8 = 0x23
	MsgPacketAck uint8 = 0x30

	// Cờ điều khiển UDP (flags bitmask)
	FlagACK     uint8 = 0x01
	FlagEOM     uint8 = 0x02
	FlagBcast   uint8 = 0x04
	FlagRetrans uint8 = 0x08
)
