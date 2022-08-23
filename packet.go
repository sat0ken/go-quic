package quic

import (
	"bytes"
	"fmt"
)

func createLongHeader(qinfo QPacketInfo, ptype int) (longHeader LongHeader, packetNum []byte) {

	// パケット番号長が2byteの場合0xC1になる
	// 先頭の6bitは110000, 下位の2bitがLenghtを表す
	// 1 LongHeader
	//  1 Fixed bit
	//   00 Packet Type
	//     00 Reserved
	// 17.2. Long Header Packets
	// That is, the length of the Packet Number field is the value of this field plus one.
	// 生成するときは1をパケット番号長から引く、2-1は1、2bitの2進数で表すと01
	// 11000001 = 0xC1 となる(Initial Packet)
	// 11100001 = 0xE1 となる(Handshake Packet)
	var firstByte byte
	switch ptype {
	case LongHeaderPacketTypeInitial:
		// とりあえず2byte
		if qinfo.ClientPacketNumberLength == 2 {
			packetNum = UintTo2byte(uint16(qinfo.InitialPacketNumber))
		} else if qinfo.ClientPacketNumberLength == 4 {
			packetNum = UintTo4byte(uint32(qinfo.InitialPacketNumber))
		}
		if len(packetNum) == 2 {
			firstByte = 0xC1
		} else if len(packetNum) == 4 {
			firstByte = 0xC3
		}
	case LongHeaderPacketTypeHandshake:
		if qinfo.ClientPacketNumberLength == 2 {
			packetNum = UintTo2byte(uint16(qinfo.HandshakePacketNumber))
		} else if qinfo.ClientPacketNumberLength == 4 {
			packetNum = UintTo4byte(uint32(qinfo.HandshakePacketNumber))
		}
		if len(packetNum) == 2 {
			firstByte = 0xE1
		} else if len(packetNum) == 4 {
			firstByte = 0xE3
		}
	}

	longHeader.HeaderByte = []byte{firstByte}
	longHeader.Version = []byte{0x00, 0x00, 0x00, 0x01}

	// destination connection idをセット
	if qinfo.DestinationConnID == nil {
		longHeader.DestConnIDLength = []byte{0x00}
	} else {
		longHeader.DestConnIDLength = []byte{byte(len(qinfo.DestinationConnID))}
		longHeader.DestConnID = qinfo.DestinationConnID
	}
	// source connection id をセット
	if qinfo.SourceConnID == nil {
		longHeader.SourceConnIDLength = []byte{0x00}
	} else {
		longHeader.SourceConnIDLength = []byte{byte(len(qinfo.SourceConnID))}
		longHeader.SourceConnID = qinfo.SourceConnID
	}

	return longHeader, packetNum
}

// Inital Packetのヘッダを生成する
func NewInitialPacket(qinfo QPacketInfo) (initPacket InitialPacket) {

	initPacket.LongHeader, initPacket.PacketNumber = createLongHeader(qinfo, LongHeaderPacketTypeInitial)
	// トークンをセット
	// トークンがnilならLengthに0だけをセットする
	// トークンがあれば可変長整数でトークンの長さをLengthにセットしてトークンをセットする
	if qinfo.Token == nil {
		initPacket.TokenLength = []byte{0x00}
	} else {
		initPacket.TokenLength = EncodeVariableInt(len(qinfo.Token))
		initPacket.Token = qinfo.Token
	}
	// Lengthを空でセット
	initPacket.Length = []byte{0x00, 0x00}

	return initPacket
}

// Handshake Packetのヘッダを生成する
func NewHandshakePacket(qinfo QPacketInfo) (handshake HandshakePacket) {

	handshake.LongHeader, handshake.PacketNumber = createLongHeader(qinfo, LongHeaderPacketTypeHandshake)

	return handshake
}

func (*InitialPacket) ToHeaderByte(initPacket InitialPacket) (headerByte []byte) {
	headerByte = toByteArr(initPacket.LongHeader)
	// set token
	if bytes.Equal(initPacket.TokenLength, []byte{0x00}) {
		headerByte = append(headerByte, initPacket.TokenLength...)
	} else {
		headerByte = append(headerByte, initPacket.TokenLength...)
		headerByte = append(headerByte, initPacket.Token...)
	}

	// パケットのLengthを可変長整数でエンコードして返す
	//if encodeLen {
	//	fmt.Printf("Init pakcet length is %x\n", initPacket.Length)
	//	headerByte = append(headerByte, EncodeVariableInt(int(sumByteArr(initPacket.Length)))...)
	//} else {
	headerByte = append(headerByte, initPacket.Length...)
	headerByte = append(headerByte, initPacket.PacketNumber...)

	return headerByte
}

func (*HandshakePacket) ToHeaderByte(handshake HandshakePacket) (packet []byte) {
	packet = toByteArr(handshake.LongHeader)
	//if encodeLen {
	//	packet = append(packet, EncodeVariableInt(int(sumByteArr(handshake.Length)))...)
	//} else {

	packet = append(packet, handshake.Length...)
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
	cryptoByte := toByteArr(NewCryptoFrame(chello, true))

	// Packet Numberが0の時、初回だけ、Client Helloのパケットを保存
	if tlsinfo.QPacketInfo.InitialPacketNumber == 0 {
		tlsinfo.HandshakeMessages = chello
	}

	// set quic keyblock
	tlsinfo.QuicKeyBlock = keyblock

	initPacket = NewInitialPacket(tlsinfo.QPacketInfo)
	// Padding Frame の長さ = 1252 - LongHeaderのLength - Crypto FrameのLength - 16(AEAD暗号化したときのOverhead)
	paddingLength := 1252 - len(initPacket.ToHeaderByte(initPacket)) - len(cryptoByte) - 16

	initPacket.Payload = UnshiftPaddingFrame(cryptoByte, paddingLength)
	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = EncodeVariableInt(length)

	// ヘッダをByteにする
	headerByte := initPacket.ToHeaderByte(initPacket)
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

// サーバからのTLS Handshakeに送り返すACKパケットを作成
func (*InitialPacket) CreateInitialAckPacket(tlsinfo TLSInfo) []byte {

	//tlsinfo.QPacketInfo.DestinationConnID = strtoByte("4a4b30eb")
	initPacket := NewInitialPacket(tlsinfo.QPacketInfo)
	// ACK Frameを作成
	ack := toByteArr(NewAckFrame(tlsinfo.QPacketInfo.AckCount))

	// Padding Frame の長さ = 1252 - LongHeaderのLength - Crypto FrameのLength - 16
	paddingLength := 1252 - len(initPacket.ToHeaderByte(initPacket)) - len(ack) - 16
	// PaddingしてPacket Sizeを増やす
	initPacket.Payload = AppendPaddingFrame(ack, paddingLength)
	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = EncodeVariableInt(length)
	// ヘッダをByteにする
	headerByte := initPacket.ToHeaderByte(initPacket)
	// PaddingとACK FrameのPayloadを暗号化する
	encpayload := EncryptClientPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, tlsinfo.QuicKeyBlock)

	// 暗号化したPayloadをヘッダとくっつける
	packet := headerByte
	packet = append(packet, encpayload...)

	// ヘッダ内のPacket Number Lengthの2bitとPacket Numberを暗号化する
	return ProtectHeader(len(headerByte)-2, packet, tlsinfo.QuicKeyBlock.ClientHeaderProtection, true)
}

// TLSのClient Finishedメッセージを送るHandshakeパケットを作成
func (*HandshakePacket) CreateHandshakePacket(tlsinfo TLSInfo) []byte {
	handshake := NewHandshakePacket(tlsinfo.QPacketInfo)

	// 1に増やす
	tlsinfo.QPacketInfo.AckCount++
	ack := NewAckFrame(tlsinfo.QPacketInfo.AckCount)
	crypto := CreateClientFinished(tlsinfo.HandshakeMessages, tlsinfo.KeyBlockTLS13.ClientFinishedKey)

	payload := toByteArr(ack)
	payload = append(payload, toByteArr(crypto)...)

	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(payload) + len(handshake.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	handshake.Length = EncodeVariableInt(length)
	// ヘッダをByteにする
	headerByte := handshake.ToHeaderByte(handshake)

	clientkey := QuicKeyBlock{
		ClientKey: tlsinfo.KeyBlockTLS13.ClientHandshakeKey,
		ClientIV:  tlsinfo.KeyBlockTLS13.ClientHandshakeIV,
	}

	// PaddingとACK FrameのPayloadを暗号化する
	encpayload := EncryptClientPayload(handshake.PacketNumber, headerByte, payload, clientkey)

	// 暗号化したPayloadをヘッダとくっつける
	packet := headerByte
	packet = append(packet, encpayload...)

	// ヘッダ内のPacket Number Lengthの2bitとPacket Numberを暗号化する
	return ProtectHeader(len(headerByte)-2, packet, tlsinfo.KeyBlockTLS13.ClientHandshakeHPKey, true)
}

// Inital packetを復号する。復号して結果をパースしてQuicパケットのframeにして返す。
func (*InitialPacket) ToPlainQuicPacket(initPacket InitialPacket, tlsinfo TLSInfo) []interface{} {

	// Initial Packetのペイロードを復号
	plain := DecryptQuicPayload(initPacket.PacketNumber, initPacket.ToHeaderByte(initPacket), initPacket.Payload, tlsinfo.QuicKeyBlock)

	// 復号した結果をパースしてQuicパケットのFrameにして返す
	return ParseQuicFrame(plain, tlsinfo.QPacketInfo.CryptoFrameOffset)

}

// Handshake packetを復号する。復号して結果をパースしてQuicパケットのframeにして返す。
func (*HandshakePacket) ToPlainQuicPacket(handshake HandshakePacket, tlsinfo TLSInfo) (frames []interface{}) {

	serverkey := QuicKeyBlock{
		ServerKey: tlsinfo.KeyBlockTLS13.ServerHandshakeKey,
		ServerIV:  tlsinfo.KeyBlockTLS13.ServerHandshakeIV,
	}
	// Handshake packetのpayloadを復号
	plain := DecryptQuicPayload(handshake.PacketNumber, handshake.ToHeaderByte(handshake), handshake.Payload, serverkey)
	// 復号した結果をパースしてQuicパケットのFrameにして返す
	return ParseQuicFrame(plain, tlsinfo.QPacketInfo.CryptoFrameOffset)
}

func (*ShortHeader) ToPlainQuicPacket(short ShortHeader, tlsinfo TLSInfo) (frames []interface{}) {

	serverkey := QuicKeyBlock{
		ServerKey: tlsinfo.KeyBlockTLS13.ServerAppKey,
		ServerIV:  tlsinfo.KeyBlockTLS13.ServerAppIV,
	}

	plain := DecryptQuicPayload(short.PacketNumber, short.ToHeaderByte(short), short.Payload, serverkey)

	// 復号した結果をパースしてQuicパケットのFrameにして返す
	return ParseQuicFrame(plain, 0)
}

func (*ShortHeader) CreateShortHeaderPacket(tlsinfo TLSInfo, payload []byte) []byte {
	// Packet Number Lengthは2byteだから01000001
	headerByte := []byte{0x41}
	headerByte = append(headerByte, tlsinfo.QPacketInfo.DestinationConnID...)
	pnumOffset := len(headerByte)

	packetnum := UintTo2byte(uint16(tlsinfo.QPacketInfo.ShortHeaderPacketNumber))
	headerByte = append(headerByte, packetnum...)

	clientkey := QuicKeyBlock{
		ClientKey: tlsinfo.KeyBlockTLS13.ClientAppKey,
		ClientIV:  tlsinfo.KeyBlockTLS13.ClientAppIV,
	}

	// PaddingとACK FrameのPayloadを暗号化する
	encpayload := EncryptClientPayload(packetnum, headerByte, payload, clientkey)
	fmt.Printf("enc payload is %x\n", encpayload)
	fmt.Printf("headerByte is %x\n", headerByte)
	// 暗号化したPayloadをヘッダとくっつける
	packet := headerByte
	packet = append(packet, encpayload...)

	// ヘッダ内のPacket Number Lengthの2bitとPacket Numberを暗号化する
	return ProtectHeader(pnumOffset, packet, tlsinfo.KeyBlockTLS13.ClientAppHPKey, false)
}
