package quic

import (
	"crypto/x509"
)

const (
	ContentTypeHandShake             = 0x16
	ContentTypeAlert                 = 0x15
	ContentTypeApplicationData       = 0x17
	HandshakeTypeClientHello         = 0x01
	HandshakeTypeServerHello         = 0x02
	HandshakeTypeNewSessionTicket    = 0x04
	HandshakeTypeEncryptedExtensions = 0x08
	HandshakeTypeClientKeyExchange   = 0x10 //=16
	HandshakeTypeCertificate         = 0x0b //=11
	HandshakeTypeServerKeyExchange   = 0x0c
	HandshakeTypeCertificateRequest  = 0x0d
	HandshakeTypeServerHelloDone     = 0x0e
	HandshakeTypeCertificateVerify   = 0x0f
	HandshakeTypeChangeCipherSpec    = 0x14 //=20
	HandshakeTypeFinished            = 0x14
	CurveIDx25519                    = 0x1D
	TLSExtSupportedVersions          = 0x2b
	TLSExtKeyShare                   = 0x33
	// application_layer_protocol_negotiation = 16
	TLSExtALPN = 0x10
	// quic_transport_parameters = 57
	TLSExtQuicTP = 0x39

	// 4.4.3. Certificate Verify
	str0x20x64 = "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
)

var TLS1_2 = []byte{0x03, 0x03}
var TLS1_3 = []byte{0x03, 0x04}

// 固定のラベル
var MasterSecretLable = []byte(`master secret`)
var KeyLable = []byte(`key expansion`)
var CLientFinishedLabel = []byte(`client finished`)
var ServerFinishedLabel = []byte(`server finished`)

// TLS1.3
var DerivedLabel = []byte(`derived`)
var ClienthsTraffic = []byte(`c hs traffic`)
var ClientapTraffic = []byte(`c ap traffic`)
var ServerhsTraffic = []byte(`s hs traffic`)
var ServerapTraffic = []byte(`s ap traffic`)
var FinishedLabel = []byte(`finished`)

// 4.4.3. Certificate Verify
//var str0x20x64 = []byte(`20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020`)
var serverCertificateContextString = []byte(`TLS 1.3, server CertificateVerify`)

// https://www.ipa.go.jp/security/rfc/RFC5246-AAJA.html
type TLSRecordHeader struct {
	ContentType     []byte
	ProtocolVersion []byte
	Length          []byte
}

type ClientHello struct {
	HandshakeType      []byte
	Length             []byte
	Version            []byte
	Random             []byte
	SessionIDLength    []byte
	SessionID          []byte
	CipherSuitesLength []byte
	CipherSuites       []byte
	CompressionLength  []byte
	CompressionMethod  []byte
	ExtensionLength    []byte
	Extensions         []byte
}

type ServerHello struct {
	HandshakeType     []byte
	Length            []byte
	Version           []byte
	Random            []byte
	SessionIDLength   []byte
	SessionID         []byte
	CipherSuites      []byte
	CompressionMethod []byte
	ExtensionLength   []byte
	TLSExtensions     []TLSExtensions
}

type TLSExtensions struct {
	Type   []byte
	Length []byte
	Value  interface{}
}

type ServerCertificate struct {
	HandshakeType                    []byte
	Length                           []byte
	CertificatesRequestContextLength []byte
	CertificatesLength               []byte
	Certificates                     []*x509.Certificate
}

// https://tex2e.github.io/rfc-translater/html/rfc8422.html
type ServerKeyExchange struct {
	HandshakeType               []byte
	Length                      []byte
	ECDiffieHellmanServerParams ECDiffieHellmanParam
}

type CertificateRequest struct {
	HandshakeType                 []byte
	Length                        []byte
	CertificateTypesCount         []byte
	CertificateTypes              []byte
	SignatureHashAlgorithmsLength []byte
	SignatureHashAlgorithms       []byte
}

type ClientCertificate struct {
	HandshakeType      []byte
	Length             []byte
	CertificatesLength []byte
	CertificateLength  []byte
	Certificate        []byte
}

// https://qiita.com/n-i-e/items/41673fd16d7bd1189a29
type ClientKeyExchange struct {
	HandshakeType []byte
	Length        []byte
	// RSA
	EncryptedPreMasterSecretLength []byte
	EncryptedPreMasterSecret       []byte
	// ECDHE
	PubkeyLength []byte
	Pubkey       []byte
}

type CertificateVerify struct {
	HandshakeType           []byte
	Length                  []byte
	SignatureHashAlgorithms []byte
	SignatureLength         []byte
	Signature               []byte
}

type ServerHelloDone struct {
	HandshakeType []byte
	Length        []byte
}

// https://www.ipa.go.jp/security/rfc/RFC5246-07JA.html#0743
type ECDiffieHellmanParam struct {
	CurveType          []byte
	NamedCurve         []byte
	PubkeyLength       []byte
	Pubkey             []byte
	SignatureAlgorithm []byte
	SignatureLength    []byte
	Signature          []byte
}

type TLSProtocol struct {
	RHeader           TLSRecordHeader
	HandshakeProtocol interface{}
}

type MasterSecretInfo struct {
	MasterSecret    []byte
	PreMasterSecret []byte
	ServerRandom    []byte
	ClientRandom    []byte
}

type KeyBlock struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
}

type HandshakeMessages struct {
	ClientHello         []byte
	ServerHello         []byte
	EncryptedExtensions []byte
	ServerCertificate   []byte
	CertificateVerify   []byte
	FinishedMessage     []byte
}

type TLSInfo struct {
	State              int
	Version            []byte
	MasterSecretInfo   MasterSecretInfo
	KeyBlockTLS13      KeyBlockTLS13
	QuicKeyBlock       QuicKeyBlock
	HandshakeMessages  []byte
	ServerHandshakeSeq int
	ServerAppSeq       int
	ClientSequenceNum  int
	ClientHandshakeSeq int
	ClientAppSeq       int
	ECDHEKeys          ECDHEKeys
	QPacketInfo        QPacketInfo
}

type QPacketInfo struct {
	DestinationConnID  []byte
	SourceConnID       []byte
	Token              []byte
	PacketNumber       int
	PacketNumberLength int
	CryptoFrameOffset  int
}

type ECDHEKeys struct {
	PrivateKey []byte
	PublicKey  []byte
	SharedKey  []byte
}

type KeyBlockTLS13 struct {
	HandshakeSecret       []byte
	ClientHandshakeSecret []byte
	ClientHandshakeKey    []byte
	ClientHandshakeHPKey  []byte //Handshake PacketののHeader Protection用に追加
	ClientHandshakeIV     []byte
	ClientFinishedKey     []byte
	ServerHandshakeSecret []byte
	ServerHandshakeKey    []byte
	ServerHandshakeHPKey  []byte //Handshake PacketののHeader Protection用に追加
	ServerHandshakeIV     []byte
	ServerFinishedKey     []byte
	MasterSecret          []byte
	ClientAppSecret       []byte
	ClientAppKey          []byte
	ClientAppHPKey        []byte
	ClientAppIV           []byte
	ServerAppSecret       []byte
	ServerAppKey          []byte
	ServerAppHPKey        []byte
	ServerAppIV           []byte
}

type EncryptedExtensions struct {
	HandshakeType   []byte
	Length          []byte
	ExtensionLength []byte
	TLSExtensions   []TLSExtensions
}

type FinishedMessage struct {
	HandshakeType []byte
	Length        []byte
	VerifyData    []byte
}

type SessionTicket struct {
	HandshakeType         []byte
	Length                []byte
	TicketLifeTime        []byte
	TicketAgeAdd          []byte
	TicketNonceLength     []byte
	TicketNonce           []byte
	TicketLength          []byte
	Ticket                []byte
	TicketExtensionLength []byte
	TicketExtensions      []byte
}

type ServerNameIndicationExtension struct {
	ServerNameListLength []byte
	ServerNameType       []byte
	ServerNameLength     []byte
	ServerName           []byte
}

type SupportedVersions struct {
	Version []byte
}

type KeyShareExtension struct {
	Group             []byte
	KeyExchangeLength []byte
	KeyExchange       []byte
}

type ALPNProtocol struct {
	ALPNExtLength []byte
	StringLength  []byte
	NextProtocol  []byte
}

type QuicParameters struct {
	Type   []byte
	Length []byte
	Value  []byte
}

type FragmentTLSPacket struct {
	Type               int
	Packet             []byte
	RemainPacketLength int
}
