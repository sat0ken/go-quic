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

		// ShortHeader = 0 で始まる
		if "0" == p0[0:1] {
			short := ParsedQuicPacket{
				Packet:     ParseShortHeaderPacket(packet, nil),
				RawPacket:  packet,
				HeaderType: 0,
			}
			rawpacket = append(rawpacket, short)
			// packetを縮める
			packet = packet[len(packet):]
			i = 0
		} else {
			// LongHeader = 1 で始まる
			switch p0[2:4] {
			// Initial Packet
			case "00":
				// 変数を宣言
				var header LongHeader
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
				parsedInit.HeaderType = 1
				parsedInit.PacketType = LongPacketTypeInitial

				rawpacket = append(rawpacket, parsedInit)

				// packetを縮める
				packet = packet[sumByteArr(initPacket.Length)+2:]
				i = 0
			// Handshake Packet
			case "10":
				var header LongHeader
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
				parsedHandshake.HeaderType = 1
				parsedHandshake.PacketType = LongPacketTypeHandshake

				rawpacket = append(rawpacket, parsedHandshake)

				// packetを縮める
				packet = packet[sumByteArr(handshake.Length)+2:]
				i = 0
			// Retry Packet
			case "11":
				var header LongHeader
				packet, header = ReadLongHeader(packet)
				retry := RetryPacket{
					LongHeader:         header,
					RetryToken:         packet[0 : len(packet)-16],
					RetryIntergrityTag: packet[len(packet)-16:],
				}
				rawpacket = append(rawpacket, ParsedQuicPacket{
					Packet:     retry,
					HeaderType: 1,
					PacketType: LongPacketTypeRetry,
				})
				// packetを縮める
				packet = packet[len(packet):]
				i = 0
			}
		}
	}

	return rawpacket
}

func ReadLongHeader(packet []byte) ([]byte, LongHeader) {
	header := LongHeader{
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

func ParseShortHeaderPacket(packet []byte, destConnId []byte) (short ShortHeader) {
	/* 17.3. Short Header Packets
	1-RTT Packet {
		Header Form (1) = 0,
		Fixed Bit (1) = 1,
		Spin Bit (1),
		Reserved Bits (2),
		Key Phase (1),
		Packet Number Length (2),
		Destination Connection ID (0..160),
		Packet Number (8..32),
		Packet Payload (8..),
	}
	*/

	short.HeaderByte = packet[0:1]

	// Short HeaderにDestination Connection IDが含まれる場合
	if destConnId != nil && bytes.Contains(packet, destConnId) {
		short.DestConnID = packet[1 : 1+len(destConnId)]
		offset := 1 + len(destConnId)
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
func UnprotectHeader(pnOffset int, packet, hpkey []byte, isLongHeader bool) []ParsedQuicPacket {
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

	encsample := make([]byte, len(sample))
	block.Encrypt(encsample, sample)

	// 保護されているヘッダの最下位4bitを解除する
	if isLongHeader {
		// Long Headerは下位4bitをmask
		packet[0] ^= encsample[0] & 0x0f
	} else {
		// Short Headerは下位5bitをmask
		packet[0] ^= encsample[0] & 0x1f
	}

	// ヘッダ保護を解除したのでパケット番号の長さを取得する
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
func ProtectHeader(pnOffset int, packet, hpkey []byte, isLongHeader bool) []byte {
	// RFC9001 5.4.2. ヘッダー保護のサンプル
	sampleOffset := pnOffset + 4

	//fmt.Printf("pnOffset is %d, sampleOffset is %d\n", pnOffset, sampleOffset)
	block, err := aes.NewCipher(hpkey)
	if err != nil {
		log.Fatalf("protect header err : %v\n", err)
	}
	sample := packet[sampleOffset : sampleOffset+16]
	//fmt.Printf("sample is %x\n", sample)
	encsample := make([]byte, len(sample))
	block.Encrypt(encsample, sample)

	// ヘッダ保護する前にパケット番号の長さを取得する
	pnlength := (packet[0] & 0x03) + 1
	/* 5.4.1. Header Protection ApplicationのFigure 6: Header Protection Pseudocode
	mask = header_protection(hp_key, sample)

	pn_length = (packet[0] & 0x03) + 1
	if (packet[0] & 0x80) == 0x80:
	# Long header: 4 bits masked
	packet[0] ^= mask[0] & 0x0f
	else:
	# Short header: 5 bits masked
	packet[0] ^= mask[0] & 0x1f

	# pn_offset is the start of the Packet Number field.
	packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]
	*/
	// ヘッダの最初のバイトを保護
	if isLongHeader {
		// Long Headerは下位4bitをmask
		packet[0] ^= encsample[0] & 0x0f
	} else {
		// Short Headerは下位5bitをmask
		packet[0] ^= encsample[0] & 0x1f
	}

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
	fmt.Printf("ServerKey is %x, ServerIV is %x\n", keyblock.ServerKey, keyblock.ServerIV)
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
	fmt.Printf("key is %x, nonce is %x, add is %x\n", keyblock.ClientKey, packetnum, header)
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
func ParseQuicFrame(packet []byte, offset int) (frame []interface{}) {
	for i := 0; i < len(packet); i++ {
		switch packet[0] {
		case ACK:
			frame = append(frame, ACKFrame{
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
			if offset == 0 {
				cframe := CryptoFrame{
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
			} else {
				cframe := CryptoFrame{
					Type: packet[0:1],
				}
				encLength := EncodeVariableInt(offset)
				// Offsetが合っているかチェック
				if !bytes.Equal(packet[1:3], encLength) {
					log.Fatal("ParseQuicFrame err : Crypto Frame offset is not equal")
				}
				cframe.Offset = packet[1:3]
				decodedLength := sumByteArr(DecodeVariableInt([]int{int(packet[3]), int(packet[4])}))
				cframe.Length = UintTo2byte(uint16(decodedLength))
				cframe.Data = packet[5 : 5+decodedLength]
				frame = append(frame, cframe)
				// パースしたフレームを取り除く
				packet = packet[5+decodedLength:]
				// 0にしてパケットを読み込む
				i = 0
			}
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

func NewCryptoFrame(data []byte, encodeLen bool) CryptoFrame {

	crypto := CryptoFrame{
		Type:   []byte{Crypto},
		Offset: []byte{0x00},
		Data:   data,
	}
	// trueなら可変長整数でエンコード
	if encodeLen {
		crypto.Length = EncodeVariableInt(len(data))
	} else {
		// Server helloのCrypto Frameはエンコードしてるけど、FinishedのCrypto Frameはエンコードせずlengthは1byteで送っている
		// 意味がわからないけどこうする
		crypto.Length = []byte{byte(len(data))}
	}

	return crypto
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

func ReadNextPacket(conn *net.UDPConn) []ParsedQuicPacket {
	recvBuf := make([]byte, 65535)
	n, _ := conn.Read(recvBuf)
	fmt.Printf("recv packet : %x\n", recvBuf[0:n])

	return ParseRawQuicPacket(recvBuf[0:n], true)
}

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
