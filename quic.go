package quic

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"net"
	"strconv"
)

func CreateQuicInitialSecret(dstConnId []byte) QuicKeyBlock {

	initSecret := hkdfExtract(dstConnId, initialSalt)
	clientInitSecret := hkdfExpandLabel(initSecret, clientInitialLabel, nil, 32)
	serverInitSecret := hkdfExpandLabel(initSecret, serverInitialLabel, nil, 32)

	return QuicKeyBlock{
		ClientKey:              hkdfExpandLabel(clientInitSecret, quicKeyLabel, nil, 16),
		ClientIV:               hkdfExpandLabel(clientInitSecret, quicIVLabel, nil, 12),
		ClientHeaderProtection: hkdfExpandLabel(clientInitSecret, quicHPLabel, nil, 16),
		ServerKey:              hkdfExpandLabel(serverInitSecret, quicKeyLabel, nil, 16),
		ServerIV:               hkdfExpandLabel(serverInitSecret, quicIVLabel, nil, 12),
		ServerHeaderProtection: hkdfExpandLabel(serverInitSecret, quicHPLabel, nil, 16),
	}
}

// QUICパケットをパースする
func ParseRawQuicPacket(packet []byte, protected bool) (rawpacket []ParsedQuicPacket) {

	for i := 0; i < len(packet); i++ {
		p0 := fmt.Sprintf("%08b", packet[0])
		// LongHeader = 1 で始まる
		// ShortHeader = 0 で始まる
		//fmt.Printf("packet type is %s\n", p0[0:1])
		switch p0[2:4] {
		// Initial Packet
		case "00":
			// 変数を宣言
			var header QuicLongHeader
			var initPacket InitialPacket
			var parsedInit ParsedQuicPacket

			// Longヘッダの処理
			packet, header = ReadLongHeader(packet)
			// Initialパケットの処理
			initPacket.LongHeader = header

			// サーバからのTokenがなければ0をセット、あればセット
			if bytes.Equal(packet[0:1], []byte{0x00}) {
				initPacket.TokenLength = packet[0:1]
				// packetを縮める
				packet = packet[1:]
			} else {
				initPacket.TokenLength = packet[0:1]
				tokenLength := sumByteArr(DecodeVariableInt([]int{int(packet[0]), int(packet[1])}))
				initPacket.Token = packet[2 : 2+tokenLength]
				// packetを縮める
				packet = packet[2+tokenLength:]
			}
			parsedInit.RawPacket = initPacket.ToHeaderByte(initPacket, false)

			// Length~を処理
			initPacket.Length, initPacket.PacketNumber, initPacket.Payload = ReadPacketLengthNumberPayload(
				packet, initPacket.LongHeader.HeaderByte, protected)

			parsedInit.Packet = initPacket
			parsedInit.RawPacket = append(parsedInit.RawPacket, packet[:sumByteArr(initPacket.Length)+2]...)
			parsedInit.Type = LongPacketTypeInitial

			rawpacket = append(rawpacket, parsedInit)

			// packetを縮める
			packet = packet[sumByteArr(initPacket.Length)+2:]
			i = 0
		// Handshake Packet
		case "10":
			var header QuicLongHeader
			var handshake HandshakePacket
			var parsedHandshake ParsedQuicPacket

			// Longヘッダの処理
			packet, header = ReadLongHeader(packet)

			// ここからHandshakeパケットの処理、Length以降を埋める
			handshake.LongHeader = header

			parsedHandshake.RawPacket = handshake.ToHeaderByte(handshake, false)

			handshake.Length, handshake.PacketNumber, handshake.Payload = ReadPacketLengthNumberPayload(
				packet, handshake.LongHeader.HeaderByte, true)

			parsedHandshake.Packet = handshake
			parsedHandshake.RawPacket = append(parsedHandshake.RawPacket, packet[:sumByteArr(handshake.Length)+2]...)
			parsedHandshake.Type = LongPacketTypeHandshake

			rawpacket = append(rawpacket, parsedHandshake)

			// packetを縮める
			packet = packet[sumByteArr(handshake.Length)+2:]
			i = 0
		// Retry Packet
		case "11":
			var header QuicLongHeader
			packet, header = ReadLongHeader(packet)
			retry := RetryPacket{
				LongHeader:         header,
				RetryToken:         packet[0 : len(packet)-16],
				RetryIntergrityTag: packet[len(packet)-16:],
			}
			rawpacket = append(rawpacket, ParsedQuicPacket{
				Packet: retry,
				Type:   LongPacketTypeRetry,
			})
			// packetを縮める
			packet = packet[len(packet):]
			i = 0
		}
	}

	return rawpacket
}

func ReadLongHeader(packet []byte) ([]byte, QuicLongHeader) {
	header := QuicLongHeader{
		HeaderByte:       packet[0:1],
		Version:          packet[1:5],
		DestConnIDLength: packet[5:6],
	}
	// Destination Connection Lengthが0ならパケットを詰める
	if bytes.Equal(header.DestConnIDLength, []byte{0x00}) {
		packet = packet[6:]
	} else {
		header.DestConnID = packet[6 : 6+int(header.DestConnIDLength[0])]
		// packetを詰める
		packet = packet[6+int(header.DestConnIDLength[0]):]
	}
	// SourceID Connection Lengthが0ならパケットを詰める
	if bytes.Equal(packet[0:1], []byte{0x00}) {
		header.SourceConnIDLength = packet[0:1]
		// packetを縮める
		packet = packet[1:]
	} else {
		header.SourceConnIDLength = packet[0:1]
		header.SourceConnID = packet[1 : 1+int(header.SourceConnIDLength[0])]
		// packetを縮める
		packet = packet[1+int(header.SourceConnIDLength[0]):]
	}
	return packet, header
}

func ParseShortHeaderPacket(packet []byte, destConnIdLength int) (short QuicShortHeaderPacket) {
	short.HeaderByte = packet[0:1]
	if destConnIdLength != 0 {
		short.DestConnID = packet[1 : 1+destConnIdLength]
		offset := 1 + destConnIdLength
		short.PacketNumber = packet[offset : offset+2]
		short.Payload = packet[offset+2:]
	} else {
		short.PacketNumber = packet[1:3]
		short.Payload = packet[3:]
	}

	return short
}

func ReadPacketLengthNumberPayload(packet, headerByte []byte, protected bool) (length, pnumber, payload []byte) {
	// Length~を処理
	if protected {
		length = packet[0:2]
		pnumber = packet[2:4]
		payload = packet[4:]
		// 可変長整数のpacket lengthをデコードする
		length = DecodeVariableInt([]int{int(length[0]), int(length[1])})
	} else {
		length = packet[0:2]
		// 可変長整数のpacket lengthをデコードする
		length = DecodeVariableInt([]int{int(length[0]), int(length[1])})
		// packet lengthで変える
		if bytes.Equal(headerByte, []byte{0xC3}) {
			// 4byteのとき
			pnumber = packet[2:6]
			payload = packet[6:]
		} else if bytes.Equal(headerByte, []byte{0xC1}) {
			// 2byteのとき
			pnumber = packet[2:4]
			payload = packet[4:]
		} else if bytes.Equal(headerByte, []byte{0xC0}) {
			// 1byteのとき
			pnumber = packet[2:3]
			payload = packet[3:]
		}
	}

	return length, pnumber, payload
}

// UnprotectHeader ヘッダ保護を解除したパケットにする
func UnprotectHeader(pnOffset int, packet, hpkey []byte) []ParsedQuicPacket {
	// https://tex2e.github.io/blog/protocol/quic-initial-packet-decrypt
	// RFC9001 5.4.2. ヘッダー保護のサンプル
	// Packet Numberの0byte目があるoffset
	sampleOffset := pnOffset + 4

	fmt.Printf("pnOffset is %d, sampleOffset is %d\n", pnOffset, sampleOffset)
	block, err := aes.NewCipher(hpkey)
	if err != nil {
		log.Fatalf("header unprotect error : %v\n", err)
	}
	sample := packet[sampleOffset : sampleOffset+16]
	PrintPacket(sample, "sample")
	encsample := make([]byte, len(sample))
	block.Encrypt(encsample, sample)

	// 保護されているヘッダの最下位4bitを解除する
	packet[0] ^= encsample[0] & 0x0f
	pnlength := (packet[0] & 0x03) + 1
	//fmt.Printf("packet number length is %d\n", pnlength)
	a := packet[pnOffset : pnOffset+int(pnlength)]
	b := encsample[1 : 1+pnlength]
	//fmt.Printf("a is %x, b is %x\n", a, b)
	for i, _ := range a {
		a[i] ^= b[i]
	}
	// 保護されていたパケット番号をセットし直す
	for i, _ := range a {
		packet[pnOffset+i] = a[i]
	}

	return ParseRawQuicPacket(packet, false)
}

// ProtectHeader パケットのヘッダを保護する
func ProtectHeader(pnOffset int, packet, hpkey []byte) []byte {
	// RFC9001 5.4.2. ヘッダー保護のサンプル
	sampleOffset := pnOffset + 4

	//fmt.Printf("pnOffset is %d, sampleOffset is %d\n", pnOffset, sampleOffset)
	block, err := aes.NewCipher(hpkey)
	if err != nil {
		log.Fatalf("protect header err : %v\n", err)
	}
	sample := packet[sampleOffset : sampleOffset+16]
	encsample := make([]byte, len(sample))
	block.Encrypt(encsample, sample)

	// ヘッダ保護する前にパケット番号の長さを取得する
	pnlength := (packet[0] & 0x03) + 1
	// ヘッダの最初のバイトを保護
	packet[0] ^= encsample[0] & 0x0f

	a := packet[pnOffset : pnOffset+int(pnlength)]
	b := encsample[1 : 1+pnlength]
	for i, _ := range a {
		a[i] ^= b[i]
	}
	// 保護したパケット番号をセットし直す
	for i, _ := range a {
		packet[pnOffset+i] = a[i]
	}
	return packet
}

func DecryptQuicPayload(packetNumber, header, payload []byte, keyblock QuicKeyBlock) []byte {
	// パケット番号で8byteのnonceにする
	packetnum := extendArrByZero(packetNumber, len(keyblock.ServerIV))

	block, _ := aes.NewCipher(keyblock.ServerKey)
	aesgcm, _ := cipher.NewGCM(block)
	// IVとxorしたのをnonceにする
	//nonce := getXORNonce(packetnum, keyblock.ClientIV)
	for i, _ := range packetnum {
		packetnum[i] ^= keyblock.ServerIV[i]
	}
	// 復号する
	//fmt.Printf("nonce is %x, add is %x, payload is %x\n", packetnum, header, payload)
	fmt.Printf("nonce is %x, header is %x\n", packetnum, header)
	plaintext, err := aesgcm.Open(nil, packetnum, payload, header)
	if err != nil {
		log.Fatalf("DecryptQuicPayload is error : %v\n", err)
	}
	return plaintext
}

// EncryptClientPayload payloadをClientKeyで暗号化
func EncryptClientPayload(packetNumber, header, payload []byte, keyblock QuicKeyBlock) []byte {
	// パケット番号で12byteのnonceにする
	packetnum := extendArrByZero(packetNumber, len(keyblock.ClientIV))
	// clientivとxorする
	for i, _ := range packetnum {
		packetnum[i] ^= keyblock.ClientIV[i]
	}
	// AES-128-GCMで暗号化する
	block, _ := aes.NewCipher(keyblock.ClientKey)
	aesgcm, _ := cipher.NewGCM(block)
	encryptedMessage := aesgcm.Seal(nil, packetnum, payload, header)

	return encryptedMessage
}

// EncryptServerPayload payloadをServerKeyで暗号化(動作確認で使うだけ)
func EncryptServerPayload(packetNumber, header, payload []byte, keyblock QuicKeyBlock) []byte {
	// パケット番号で12byteのnonceにする
	packetnum := extendArrByZero(packetNumber, len(keyblock.ServerIV))
	// clientivとxorする
	for i, _ := range packetnum {
		packetnum[i] ^= keyblock.ServerIV[i]
	}
	// AES-128-GCMで暗号化する
	block, _ := aes.NewCipher(keyblock.ServerKey)
	aesgcm, _ := cipher.NewGCM(block)
	encryptedMessage := aesgcm.Seal(nil, packetnum, payload, header)

	return encryptedMessage
}

// 復号化されたQUICパケットのフレームをパースする
func ParseQuicFrame(packet []byte) (frame []interface{}) {
	for i := 0; i < len(packet); i++ {
		switch packet[0] {
		case ACK:
			frame = append(frame, ACKFrames{
				Type:                packet[0:1],
				LargestAcknowledged: packet[1:2],
				AckDelay:            packet[2:3],
				AckRangeCount:       packet[3:4],
				FirstAckRange:       packet[4:5],
			})
			// パースしたフレームを取り除く
			packet = packet[5:]
			// 0にしてパケットを読み込む
			i = 0
		case Crypto:
			cframe := CryptoFrames{
				Type:   packet[0:1],
				Offset: packet[1:2],
			}
			decodedLength := sumByteArr(DecodeVariableInt([]int{int(packet[2]), int(packet[3])}))
			cframe.Length = UintTo2byte(uint16(decodedLength))
			cframe.Data = packet[4 : 4+decodedLength]
			frame = append(frame, cframe)
			// パースしたフレームを取り除く
			packet = packet[4+decodedLength:]
			// 0にしてパケットを読み込む
			i = 0
		case NewConnectionID:
			newconn := NewConnectionIdFrame{
				Type:               packet[0:1],
				SequenceNumber:     packet[1:2],
				RetirePriotTo:      packet[2:3],
				ConnectionIDLength: packet[3:4],
			}
			length := int(newconn.ConnectionIDLength[0])
			newconn.ConnectionID = packet[4 : 4+length]
			// Stateless Reset Token (128) = 128bit なので 16byte
			newconn.StatelessResetToken = packet[4+length : 4+length+16]
			frame = append(frame, newconn)
			// パースしたフレームを取り除く
			packet = packet[4+length+16:]
			// 0にしてパケットを読み込む
			i = 0
		}
	}
	return frame
}

// Inital Packetを生成する
func NewInitialPacket(destConnID, sourceConnID, token []byte, pnum, pnumlen uint) InitialPacket {
	// とりあえず2byte
	var packetNum []byte
	if pnumlen == 2 {
		packetNum = UintTo2byte(uint16(pnum))
	} else if pnumlen == 4 {
		packetNum = UintTo4byte(uint32(pnum))
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
	longHeader := QuicLongHeader{
		HeaderByte:       []byte{firstByte},
		Version:          []byte{0x00, 0x00, 0x00, 0x01},
		DestConnIDLength: []byte{byte(len(destConnID))},
		DestConnID:       destConnID,
	}
	// source connectio id をセット
	if sourceConnID == nil {
		longHeader.SourceConnIDLength = []byte{0x00}
	} else {
		longHeader.SourceConnIDLength = []byte{byte(len(sourceConnID))}
		longHeader.SourceConnID = sourceConnID
	}

	var initPacket InitialPacket
	initPacket.LongHeader = longHeader
	// トークンをセット
	// トークンがnilならLengthに0だけをセットする
	// トークンがあれば可変長整数でトークンの長さをLengthにセットしてトークンをセットする
	if token == nil {
		initPacket.TokenLength = []byte{0x00}
	} else {
		initPacket.TokenLength = EncodeVariableInt(len(token))
		initPacket.Token = token
	}
	// packet numberをセット
	initPacket.PacketNumber = packetNum
	// Lengthを空でセット
	initPacket.Length = []byte{0x00, 0x00}

	return initPacket
}

func (*HandshakePacket) NewHandshakePacket(destConnID, sourceConnID []byte, pnum, pnumlen uint) HandshakePacket {
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
	longHeader := QuicLongHeader{
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

	var handshake HandshakePacket
	handshake.LongHeader = longHeader
	handshake.PacketNumber = packetNum

	return handshake
}

// RFC9000 A.1. サンプル可変長整数デコード
func DecodeVariableInt(plength []int) []byte {
	v := plength[0]
	prefix := v >> 6
	length := 1 << prefix

	v = v & 0x3f
	for i := 0; i < length-1; i++ {
		v = (v << 8) + plength[1]
	}
	//fmt.Printf("%x %d\n", v, v)
	return UintTo2byte(uint16(v))
}

// RFC9000 16. 可変長整数エンコーディング
// 2byteのエンコードしか実装してない
func EncodeVariableInt(length int) []byte {
	var enc uint64
	s := fmt.Sprintf("%b", length)
	if length <= 16383 {
		var zero string
		//0-16383は14bitなので足りないbitは0で埋める
		padding := 14 - len(s)
		for i := 0; i < padding; i++ {
			zero += "0"
		}
		// 2MSBは01で始める
		enc, _ = strconv.ParseUint(fmt.Sprintf("01%s%s", zero, s), 2, 16)
	}
	return UintTo2byte(uint16(enc))
}

func NewQuicCryptoFrame(data []byte) CryptoFrames {
	return CryptoFrames{
		Type:   []byte{Crypto},
		Offset: []byte{0x00},
		Length: EncodeVariableInt(len(data)),
		Data:   data,
	}
}

func ConnectQuicServer(server []byte, port int) *net.UDPConn {
	serverInfo := net.UDPAddr{
		IP:   server,
		Port: port,
	}
	conn, err := net.DialUDP("udp", nil, &serverInfo)
	if err != nil {
		log.Fatalf("Can't connect quic server : %v", err)
	}
	return conn
}

func SendQuicPacket(conn *net.UDPConn, data []byte) []ParsedQuicPacket {
	recvBuf := make([]byte, 65535)

	conn.Write(data)
	n, _ := conn.Read(recvBuf)

	fmt.Printf("recv packet : %x\n", recvBuf[0:n])

	return ParseRawQuicPacket(recvBuf[0:n], true)
}

//func NewUDPSocket() int {
//	sendfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
//	if err != nil {
//		log.Fatalf("create socket err : %v\n", err)
//	}
//	//syscall.SetsockoptInt(sendfd, syscall.SOL_IP, syscall.IP_MTU_DISCOVER, 2)
//	// UDP packetを受信するためにbindする
//	syscall.Bind(sendfd, &syscall.SockaddrInet4{
//		Addr: [4]byte{127, 0, 0, 1},
//		Port: 42279,
//	})
//	return sendfd
//}
//
//func SendToQuicServer(senfd int, packet []byte) []byte {
//
//	addr := syscall.SockaddrInet4{
//		Addr: [4]byte{127, 0, 0, 1},
//		Port: 18443,
//	}
//	err := syscall.Sendto(senfd, packet, 0, &addr)
//	if err != nil {
//		log.Fatalf("send packet err : %v\n", err)
//	}
//	//for {
//	buffer := make([]byte, 65535)
//	oob := make([]byte, 65535)
//	n, oobn, _, _, err := syscall.Recvmsg(senfd, buffer, oob, syscall.MSG_OOB)
//	//n, _, err := syscall.Recvfrom(senfd, buffer, 0)
//	if err != nil {
//		log.Fatalf("recv err : %v", err)
//	}
//	fmt.Printf("recv packet is %d,  %x\n", n, buffer[:n])
//	fmt.Printf("recv oob is %x\n", buffer[:oobn])
//	return buffer[:n]
//	//}
//}

// paddingフレームを読み飛ばして、QUICのフレームを配列に入れて返す
func SkipPaddingFrame(packet []byte) [][]byte {
	var framesByte [][]byte

	for i := 0; i < len(packet); i++ {
		// ACK
		if packet[i] == 0x02 {
			framesByte = append(framesByte, packet[i:i+5])
			i += 4
		} else if packet[i] == 0x06 { // Crypto Frame
			length := packet[i+2 : i+4]
			// 可変長整数をデコードする
			decodedLength := sumByteArr(DecodeVariableInt([]int{int(length[0]), int(length[1])}))
			//cryptoData := packet[i+4 : i+4+int(decodedLength)]
			framesByte = append(framesByte, packet[i:i+4+int(decodedLength)])
			i += 4 + int(decodedLength)
		}
	}

	return framesByte
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

// Initial Packetを生成してTLSの鍵情報と返す
func CreateInitialPacket(dcid, token []byte, pnum uint) (TLSInfo, []byte) {
	// Destination Connection IDからInitial Packetの暗号化に使う鍵を生成する
	keyblock := CreateQuicInitialSecret(dcid)

	tlsinfo, chelloByte := NewQuicClientHello()
	cryptoByte := toByteArr(NewQuicCryptoFrame(chelloByte))

	initPacket := NewInitialPacket(dcid, nil, token, pnum, 2)
	// Padding Frame の長さ = 1252 - LongHeaderのLength - Crypto FrameのLength - 16
	paddingLength := 1252 - len(initPacket.ToHeaderByte(initPacket, false)) - len(cryptoByte) - 16

	initPacket.Payload = UnshiftPaddingFrame(cryptoByte, paddingLength)
	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = EncodeVariableInt(length)

	// ヘッダをByteにする
	headerByte := initPacket.ToHeaderByte(initPacket, false)
	//fmt.Printf("header is %x\n", headerByte)

	// Padding+Crypto FrameのPayloadを暗号化する
	encpayload := EncryptClientPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)

	// 暗号化したPayloadをヘッダとくっつける
	packet := headerByte
	packet = append(packet, encpayload...)
	// ヘッダ内のPacket Number Lengthの2bitとPacket Numberを暗号化する
	protectPacket := ProtectHeader(len(headerByte)-2, packet, keyblock.ClientHeaderProtection)

	return tlsinfo, protectPacket
}
