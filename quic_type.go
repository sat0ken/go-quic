package quic

const (
	Ping            = 0x01
	ACK             = 0x02
	Crypto          = 0x06
	NewToken        = 0x07
	HandShakeDone   = 0x1e
	NewConnectionID = 0x18
)

const (
	LongHeaderPacketTypeInitial = iota
	LongHeaderPacketTypeORTT
	LongHeaderPacketTypeHandshake
	LongHeaderPacketTypeRetry
)

const (
	originalDistinationConnectionID = iota
	maxIdleTimeOut
	statelessResetToken
	maxUDPPayloadSize
	initialMaxData
	initialMaxStreamDataBidiLocal
	initialMaxStreamDataBidiRemote
	initialMaxStreamDataUni
	initialMaxStreamsBidi
	initialMaxStreamsUni
	ackDelayExponent
	maxAckDelay
	disableActiveMigration
	preferredAddress
	activeConnectionIdLimit
	initialSourceConnectionID
	retrySourceConnectionID
	maxDatagramFrameSize = 0x20
)

// https://www.iana.org/assignments/quic/quic.xhtml
// quic trasnsport parameters type
var quicTransportPrameterMaps = map[string]int{
	"originalDistinationConnectionID": originalDistinationConnectionID,
	"maxIdleTimeOut":                  maxIdleTimeOut,
	"statelessResetToken":             statelessResetToken,
	"maxUDPPayloadSize":               maxUDPPayloadSize,
	"initialMaxDataType":              initialMaxData,
	"initialMaxStreamDataBidiLocal":   initialMaxStreamDataBidiLocal,
	"initialMaxStreamDataBidiRemote":  initialMaxStreamDataBidiRemote,
	"initialMaxStreamDataUni":         initialMaxStreamDataUni,
	"initialMaxStreamsBidi":           initialMaxStreamsBidi,
	"initialMaxStreamsUni":            initialMaxStreamsUni,
	"ackDelayExponent":                ackDelayExponent,
	"maxAckDelay":                     maxAckDelay,
	"disableActiveMigration":          disableActiveMigration,
	"preferredAddress":                preferredAddress,
	"activeConnectionIdLimit":         activeConnectionIdLimit,
	"initialSourceConnectionID":       initialSourceConnectionID,
	"retrySourceConnectionID":         retrySourceConnectionID,
	"maxDatagramFrameSize":            maxDatagramFrameSize,
	//TODO: ここから下はいるのか？ quic-goはまでmaxDatagramFrameSizeしか定義してないな
	//"discard":                            0x173e,
	//"greaseBit":                          0x2ab2,
	//"initialRtt":                         0x3127,
	//"googleConnectionOptions":            0x3128,
	//"userAgent":                          0x3129,
	//"googleVersion":                      0x3130,
	//"versionInformation":                 0xFF73DB,
}

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
var initialMaxStreamDataBidiLocalParamByte = []byte{initialMaxStreamDataBidiLocal, 0x04, 0x80, 0x08, 0x00, 0x00}
var initialMaxStreamDataBidiRemoteParamByte = []byte{initialMaxStreamDataBidiRemote, 0x04, 0x80, 0x08, 0x00, 0x00}
var initialMaxStreamDataUniParamByte = []byte{initialMaxStreamDataUni, 0x04, 0x80, 0x08, 0x00, 0x00}
var initialMaxDataParamByte = []byte{initialMaxData, 0x04, 0x80, 0x0c, 0x00, 0x00}
var initialMaxStreamsBidiParamByte = []byte{initialMaxStreamsBidi, 0x02, 0x40, 0x64}
var initialMaxStreamsUniParamByte = []byte{initialMaxStreamsUni, 0x02, 0x40, 0x64}
var maxIdleTimeoutParamByte = []byte{maxIdleTimeOut, 0x04, 0x80, 0x00, 0x75, 0x30}
var maxUdpPayloadSizeParamByte = []byte{maxUDPPayloadSize, 0x02, 0x45, 0xac}
var disableActiveMigrationParamByte = []byte{disableActiveMigration, 0x00}
var activeConnectionIdLimitParamByte = []byte{activeConnectionIdLimit, 0x01, 0x04}
var initialSourceConnectionIdParamByte = []byte{initialSourceConnectionID, 0x00}
var maxDatagramFrameSizeParamByte = []byte{maxDatagramFrameSize, 0x01, 0x00}

type QuicKeyBlock struct {
	ClientKey              []byte
	ClientIV               []byte
	ClientHeaderProtection []byte
	ServerKey              []byte
	ServerIV               []byte
	ServerHeaderProtection []byte
}

type ParsedQuicPacket struct {
	Packet     interface{}
	RawPacket  []byte
	HeaderType int
	PacketType int
}

type LongHeader struct {
	HeaderByte         []byte
	Version            []byte
	DestConnIDLength   []byte
	DestConnID         []byte
	SourceConnIDLength []byte
	SourceConnID       []byte
}

type ShortHeader struct {
	HeaderByte   []byte
	DestConnID   []byte
	PacketNumber []byte
	Payload      []byte
}

type InitialPacket struct {
	LongHeader   LongHeader
	TokenLength  []byte
	Token        []byte
	Length       []byte
	PacketNumber []byte
	Payload      []byte
}

type RetryPacket struct {
	LongHeader         LongHeader
	RetryToken         []byte
	RetryIntergrityTag []byte
}

type HandshakePacket struct {
	LongHeader   LongHeader
	Length       []byte
	PacketNumber []byte
	Payload      []byte
}

// 19.6. CRYPTO Frames
type CryptoFrame struct {
	Type   []byte
	Offset []byte
	Length []byte
	Data   []byte
}

type ACKFrame struct {
	Type                []byte
	LargestAcknowledged []byte
	AckDelay            []byte
	AckRangeCount       []byte
	FirstAckRange       []byte
}

type NewConnectionIdFrame struct {
	Type                []byte
	SequenceNumber      []byte
	RetirePriotTo       []byte
	ConnectionIDLength  []byte
	ConnectionID        []byte
	StatelessResetToken []byte
}

// 19.8. STREAM Frames
type StreamFrame struct {
	Type       []byte
	StreamID   []byte
	Offset     []byte
	Length     []byte
	StreamData []byte
}

type QPacketInfo struct {
	DestinationConnID      []byte
	SourceConnID           []byte
	Token                  []byte
	InitialPacketNumber    int // Initialパケットのパケット番号
	HandshakePacketNumber  int // Handshakeパケットのパケット番号
	ShortHeaderPacketNmber int // 1RTTパケットのパケット番号
	PacketNumberLength     int
	CryptoFrameOffset      int
	AckCount               int
}
