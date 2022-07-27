package quic

const (
	Ping          = 0x01
	ACK           = 0x02
	Crypto        = 0x06
	NewToken      = 0x07
	HandShakeDone = 0x1e
)

const (
	LongPacketTypeInitial = iota
	LongPacketTypeORTT
	LongPacketTypeHandshake
	LongPacketTypeRetry
)

// https://www.iana.org/assignments/quic/quic.xhtml
// quic trasnsport parameters type
const (
	originalDistinationConnectionID    = 0x00
	maxIdleTimeOut                     = 0x01
	statelessResetToken                = 0x02
	maxUDPPayloadSize                  = 0x03
	initialMaxDataType                 = 0x04
	initialMaxStreamDataBidiLocalType  = 0x05
	initialMaxStreamDataBidiRemoteType = 0x06
	initialMaxStreamDataUniType        = 0x07
	initialMaxStreamsBidiType          = 0x08
	initialMaxStreamsUniType           = 0x09
	ackDelayExponent                   = 0x0a
	maxAckDelay                        = 0x0b
	disableActiveMigrationType         = 0x0c
	preferredAddress                   = 0x0d
	activeConnectionIdLimitType        = 0x0e
	initialSourceConnectionID          = 0x0f
	retrySourceConnectionID            = 0x10
	maxDatagramFrameSizeType           = 0x11
	discard                            = 0x173e
	greaseBit                          = 0x2ab2
	initialRtt                         = 0x3127
	googleConnectionOptions            = 0x3128
	userAgent                          = 0x3129
	googleVersion                      = 0x3130
	versionInformation                 = 0xFF73DB
)

var initialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// 固定のラベル
var clientInitialLabel = []byte(`client in`)
var serverInitialLabel = []byte(`server in`)
var quicKeyLabel = []byte(`quic key`)
var quicIVLabel = []byte(`quic iv`)

// hp is for header protection
var quicHPLabel = []byte(`quic hp`)

// Quic Transport Prameters
// 18.2. Transport Parameter Definitions
var initialMaxStreamDataBidiLocal = []byte{0x05, 0x04, 0x80, 0x08, 0x00, 0x00}
var initialMaxStreamDataBidiRemote = []byte{0x06, 0x04, 0x80, 0x08, 0x00, 0x00}
var initialMaxStreamDataUni = []byte{0x07, 0x04, 0x80, 0x08, 0x00, 0x00}
var initialMaxData = []byte{0x04, 0x04, 0x80, 0x0c, 0x00, 0x00}
var initialMaxStreamsBidi = []byte{0x08, 0x01, 0x00}
var initialMaxStreamsUni = []byte{0x09, 0x02, 0x40, 0x64}
var maxIdleTimeout = []byte{0x01, 0x04, 0x80, 0x00, 0x75, 0x30}
var maxUdpPayloadSize = []byte{0x03, 0x02, 0x45, 0xac}
var disableActiveMigration = []byte{0x0c, 0x00}
var activeConnectionIdLimit = []byte{0x0e, 0x01, 0x04}
var initialSourceConnectionId = []byte{0x0f, 0x00}
var maxDatagramFrameSize = []byte{0x20, 0x01, 0x00}

type QuicKeyBlock struct {
	ClientKey              []byte
	ClientIV               []byte
	ClientHeaderProtection []byte
	ServerKey              []byte
	ServerIV               []byte
	ServerHeaderProtection []byte
}

type QuicRawPacket struct {
	QuicHeader interface{}
	QuicFrames []interface{}
}

type QuicLongHeader struct {
	HeaderByte         []byte
	Version            []byte
	DestConnIDLength   []byte
	DestConnID         []byte
	SourceConnIDLength []byte
	SourceConnID       []byte
}

type InitialPacket struct {
	LongHeader   QuicLongHeader
	TokenLength  []byte
	Token        []byte
	Length       []byte
	PacketNumber []byte
	Payload      []byte
}

type RetryPacket struct {
	LongHeader         QuicLongHeader
	RetryToken         []byte
	RetryIntergrityTag []byte
}

type HandshakePacket struct {
	LongHeader   QuicLongHeader
	Length       []byte
	PacketNumber []byte
	Payload      []byte
}

type CryptoFrames struct {
	Type   []byte
	Offset []byte
	Length []byte
	Data   []byte
}

type ACKFrames struct {
	Type                []byte
	LargestAcknowledged []byte
	AckDelay            []byte
	AckRangeCount       []byte
	FirstAckRange       []byte
}

type UDPInfo struct {
	ClientAddr []byte
	ClientPort int
	ServerAddr []byte
	ServerPort int
}
