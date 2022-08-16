package quic

import (
	"bytes"
)

// Inital Packetを生成する
func NewInitialPacket(qinfo QPacketInfo) (initPacket InitialPacket) {
	// とりあえず2byte
	var packetNum []byte
	if qinfo.PacketNumberLength == 2 {
		packetNum = UintTo2byte(uint16(qinfo.PacketNumber))
	} else if qinfo.PacketNumberLength == 4 {
		packetNum = UintTo4byte(uint32(qinfo.PacketNumber))
	}

	// パケット番号長が2byteの場合0xC1になる
	// 先頭の6bitは110000, 下位の2bitがLenghtを表す
	// 1 LongHeader
	//  1 Fixed bit
	//   00 Packet Type
	//     00 Reserved
	// 17.2. Long Header Packets
	// That is, the length of the Packet Number field is the value of this field plus one.
	// 生成するときは1をパケット番号長から引く、2-1は1、2bitの2進数で表すと01
	// 11000001 = 0xC1 となる
	var firstByte byte
	if len(packetNum) == 2 {
		firstByte = 0xC1
	} else if len(packetNum) == 4 {
		firstByte = 0xC3
	}
	// Headerを作る
	longHeader := LongHeader{
		HeaderByte:       []byte{firstByte},
		Version:          []byte{0x00, 0x00, 0x00, 0x01},
		DestConnIDLength: []byte{byte(len(qinfo.DestinationConnID))},
		DestConnID:       qinfo.DestinationConnID,
	}
	// source connectio id をセット
	if qinfo.SourceConnID == nil {
		longHeader.SourceConnIDLength = []byte{0x00}
	} else {
		longHeader.SourceConnIDLength = []byte{byte(len(qinfo.SourceConnID))}
		longHeader.SourceConnID = qinfo.SourceConnID
	}

	initPacket.LongHeader = longHeader
	// トークンをセット
	// トークンがnilならLengthに0だけをセットする
	// トークンがあれば可変長整数でトークンの長さをLengthにセットしてトークンをセットする
	if qinfo.Token == nil {
		initPacket.TokenLength = []byte{0x00}
	} else {
		initPacket.TokenLength = EncodeVariableInt(len(qinfo.Token))
		initPacket.Token = qinfo.Token
	}
	// packet numberをセット
	initPacket.PacketNumber = packetNum
	// Lengthを空でセット
	initPacket.Length = []byte{0x00, 0x00}

	return initPacket
}

func NewHandshakePacket(destConnID, sourceConnID []byte, pnum, pnumlen uint) (handshake HandshakePacket) {
	// とりあえず2byte
	var packetNum []byte
	if pnumlen == 2 {
		packetNum = UintTo2byte(uint16(pnum))
	} else if pnumlen == 4 {
		packetNum = UintTo4byte(uint32(pnum))
	}

	var firstByte byte
	if len(packetNum) == 2 {
		firstByte = 0xC1
	} else if len(packetNum) == 4 {
		firstByte = 0xC3
	}
	// Headerを作る
	longHeader := LongHeader{
		HeaderByte: []byte{firstByte},
		Version:    []byte{0x00, 0x00, 0x00, 0x01},
	}
	// destination connection idをセット
	if destConnID == nil {
		longHeader.DestConnIDLength = []byte{0x00}
	}
	// source connection id をセット
	if sourceConnID == nil {
		longHeader.SourceConnIDLength = []byte{0x00}
	} else {
		longHeader.SourceConnIDLength = []byte{byte(len(sourceConnID))}
		longHeader.SourceConnID = sourceConnID
	}

	handshake.LongHeader = longHeader
	handshake.PacketNumber = packetNum

	return handshake
}

func (*InitialPacket) ToHeaderByte(initPacket InitialPacket, encodeLen bool) (headerByte []byte) {
	headerByte = toByteArr(initPacket.LongHeader)
	// set token
	if bytes.Equal(initPacket.TokenLength, []byte{0x00}) {
		headerByte = append(headerByte, initPacket.TokenLength...)
	} else {
		headerByte = append(headerByte, initPacket.TokenLength...)
		headerByte = append(headerByte, initPacket.Token...)
	}

	// パケットのLengthを可変長整数でエンコードして返す
	if encodeLen {
		headerByte = append(headerByte, EncodeVariableInt(int(sumByteArr(initPacket.Length)))...)
	} else {
		headerByte = append(headerByte, initPacket.Length...)
	}

	headerByte = append(headerByte, initPacket.PacketNumber...)
	return headerByte
}

func (*HandshakePacket) ToHeaderByte(handshake HandshakePacket, encodeLen bool) (packet []byte) {
	packet = toByteArr(handshake.LongHeader)
	if encodeLen {
		packet = append(packet, EncodeVariableInt(int(sumByteArr(handshake.Length)))...)
	} else {
		packet = append(packet, handshake.Length...)
	}
	packet = append(packet, handshake.PacketNumber...)

	return packet
}

func (*ShortHeader) ToHeaderByte(short ShortHeader) (header []byte) {
	header = append(header, short.HeaderByte...)
	header = append(header, short.DestConnID...)
	header = append(header, short.PacketNumber...)

	return header
}

// Initial Packetを生成してTLSの鍵情報と返す
func (*InitialPacket) CreateInitialPacket(tlsinfo TLSInfo) (TLSInfo, []byte) {
	var chello []byte
	var initPacket InitialPacket
	// Destination Connection IDからInitial Packetの暗号化に使う鍵を生成する
	keyblock := CreateQuicInitialSecret(tlsinfo.QPacketInfo.DestinationConnID)

	tlsinfo.ECDHEKeys, chello = NewQuicClientHello()
	cryptoByte := toByteArr(NewQuicCryptoFrame(chello))

	// Packet Numberが0の時だけ、Client Helloのパケットを保存
	if tlsinfo.QPacketInfo.PacketNumber == 0 {
		tlsinfo.HandshakeMessages = chello
	}

	// set quic keyblock
	tlsinfo.QuicKeyBlock = keyblock

	initPacket = NewInitialPacket(tlsinfo.QPacketInfo)
	// Padding Frame の長さ = 1252 - LongHeaderのLength - Crypto FrameのLength - 16(AEAD暗号化したときのOverhead)
	paddingLength := 1252 - len(initPacket.ToHeaderByte(initPacket, false)) - len(cryptoByte) - 16

	initPacket.Payload = UnshiftPaddingFrame(cryptoByte, paddingLength)
	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = EncodeVariableInt(length)

	// ヘッダをByteにする
	headerByte := initPacket.ToHeaderByte(initPacket, false)
	//fmt.Printf("header is %x\n", headerByte)

	// PaddingとCrypto FrameのPayloadを暗号化する
	encpayload := EncryptClientPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)

	// 暗号化したPayloadをヘッダとくっつける
	packet := headerByte
	packet = append(packet, encpayload...)
	// ヘッダ内のPacket Number Lengthの2bitとPacket Numberを暗号化する
	protectPacket := ProtectHeader(len(headerByte)-2, packet, keyblock.ClientHeaderProtection, true)

	return tlsinfo, protectPacket
}

func (*InitialPacket) CreateInitialAckPacket(tlsinfo TLSInfo) []byte {

	tlsinfo.QPacketInfo.DestinationConnID = strtoByte("4a4b30eb")
	initPacket := NewInitialPacket(tlsinfo.QPacketInfo)
	ack := []byte{0x02, 0x00, 0x00, 0x00, 0x00}

	// Padding Frame の長さ = 1252 - LongHeaderのLength - Crypto FrameのLength - 16
	paddingLength := 1252 - len(initPacket.ToHeaderByte(initPacket, false)) - len(ack) - 16
	// PaddingしてPacket Sizeを増やす
	initPacket.Payload = AppendPaddingFrame(ack, paddingLength)
	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = EncodeVariableInt(length)
	// ヘッダをByteにする
	headerByte := initPacket.ToHeaderByte(initPacket, false)
	// PaddingとACK FrameのPayloadを暗号化する
	encpayload := EncryptClientPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, tlsinfo.QuicKeyBlock)

	// 暗号化したPayloadをヘッダとくっつける
	packet := headerByte
	packet = append(packet, encpayload...)

	// ヘッダ内のPacket Number Lengthの2bitとPacket Numberを暗号化する
	return ProtectHeader(len(headerByte)-2, packet, tlsinfo.QuicKeyBlock.ClientHeaderProtection, true)
}

// Inital packetを復号する。復号して結果をパースしてQuicパケットのframeにして返す。
func (*InitialPacket) ToPlainQuicPacket(initPacket InitialPacket, rawPacket []byte, tlsinfo TLSInfo) (frames []interface{}) {
	startPnumOffset := len(initPacket.ToHeaderByte(initPacket, false)) - 2

	// ヘッダ保護を解除したInitial Packetにする
	parsed := UnprotectHeader(startPnumOffset, rawPacket, tlsinfo.QuicKeyBlock.ServerHeaderProtection, true)
	unpInit := parsed[0].Packet.(InitialPacket)

	// Initial Packetのペイロードを復号
	plain := DecryptQuicPayload(unpInit.PacketNumber, unpInit.ToHeaderByte(unpInit, true), unpInit.Payload, tlsinfo.QuicKeyBlock)

	// 復号した結果をパースしてQuicパケットのFrameにして返す
	return ParseQuicFrame(plain, tlsinfo.QPacketInfo.CryptoFrameOffset)
}

// Handshake packetを復号する。復号して結果をパースしてQuicパケットのframeにして返す。
func (*HandshakePacket) ToPlainQuicPacket(handshake HandshakePacket, rawpacket []byte, tlsinfo TLSInfo) (frames []interface{}) {
	startPnumOffset := len(handshake.ToHeaderByte(handshake, false)) - 2

	// 鍵導出で生成したHandshake packet用のヘッダ保護キーでヘッダ保護を解除したパケットにする
	parsed := UnprotectHeader(startPnumOffset, rawpacket, tlsinfo.KeyBlockTLS13.ServerHandshakeHPKey, true)
	unpHandshake := parsed[0].Packet.(HandshakePacket)

	serverkey := QuicKeyBlock{
		ServerKey: tlsinfo.KeyBlockTLS13.ServerHandshakeKey,
		ServerIV:  tlsinfo.KeyBlockTLS13.ServerHandshakeIV,
	}
	// Handshake packetのpayloadを復号
	plain := DecryptQuicPayload(unpHandshake.PacketNumber, unpHandshake.ToHeaderByte(unpHandshake, true), unpHandshake.Payload, serverkey)
	// 復号した結果をパースしてQuicパケットのFrameにして返す
	return ParseQuicFrame(plain, tlsinfo.QPacketInfo.CryptoFrameOffset)
}

func (*ShortHeader) ToPlainQuicPacket(short ShortHeader, rawpacket []byte, tlsinfo TLSInfo) (frames []interface{}) {
	startPnumOffset := len(short.ToHeaderByte(short)) - 2

	// 鍵導出で生成したHandshake packet用のヘッダ保護キーでヘッダ保護を解除したパケットにする
	parsed := UnprotectHeader(startPnumOffset, rawpacket, tlsinfo.KeyBlockTLS13.ServerAppHPKey, false)
	unpShort := parsed[0].Packet.(ShortHeader)

	serverkey := QuicKeyBlock{
		ServerKey: tlsinfo.KeyBlockTLS13.ServerAppKey,
		ServerIV:  tlsinfo.KeyBlockTLS13.ServerAppIV,
	}

	plain := DecryptQuicPayload(unpShort.PacketNumber, unpShort.ToHeaderByte(unpShort), unpShort.Payload, serverkey)

	// 復号した結果をパースしてQuicパケットのFrameにして返す
	return ParseQuicFrame(plain, 0)
}
