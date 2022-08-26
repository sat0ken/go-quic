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
func ParseRawQuicPacket(packet []byte, tlsinfo TLSInfo) (ParsedQuicPacket, []byte) {
	var parsedPacket ParsedQuicPacket

	p0 := fmt.Sprintf("%08b", packet[0])
	// ShortHeader = 0 で始まる
	if "0" == p0[0:1] {
		var unp []byte

		// ヘッダ保護された状態のShort Headerをパースする
		shortHeader := ParseShortHeaderPacket(packet, tlsinfo.QPacketInfo, true)
		startPnumOffset := len(shortHeader.ToHeaderByte(shortHeader))

		// ヘッダ保護を解除する
		unp, tlsinfo = UnprotectHeader(startPnumOffset, packet, tlsinfo.KeyBlockTLS13.ServerAppHPKey, false, tlsinfo)
		parsedPacket = ParsedQuicPacket{
			// ヘッダ保護を解除したパケットをパースする
			Packet:     ParseShortHeaderPacket(unp, tlsinfo.QPacketInfo, false),
			RawPacket:  packet,
			HeaderType: 0,
		}
		packet = packet[len(packet):]
	} else {
		// LongHeader = 1 で始まる
		switch p0[2:4] {
		// Initial Packet
		case "00":
			var unp []byte

			// Long Header Packetをパースする
			init, _ := ParseLongHeaderPacket(packet, LongHeaderPacketTypeInitial, true, 0)
			parsedProtect := init.(InitialPacket)
			headerByte := parsedProtect.ToHeaderByte(parsedProtect)
			fmt.Printf("headerByte is %x\n", headerByte)
			// ヘッダ保護を解除する
			unp, tlsinfo = UnprotectHeader(len(headerByte), packet, tlsinfo.QuicKeyBlock.ServerHeaderProtection, true, tlsinfo)
			// ヘッダ保護を解除したパケットをパースする
			parsedUnprotect, plen := ParseLongHeaderPacket(unp, LongHeaderPacketTypeInitial, false, tlsinfo.QPacketInfo.ServerPacketNumberLength)
			unpInit := parsedUnprotect.(InitialPacket)

			parsedPacket = ParsedQuicPacket{
				// ヘッダ保護を解除したLong Header Packetをパースする
				Packet:     unpInit,
				HeaderType: 1,
				PacketType: LongHeaderPacketTypeInitial,
			}

			// 暗号化するときのOverHeadを足す
			plen += 16
			// packetを縮める
			packet = packet[plen:]
		// Handshake Packet
		case "10":
			var unp []byte

			// Long Header Packetをパースする
			parsedProtect, _ := ParseLongHeaderPacket(packet, LongHeaderPacketTypeHandshake, true, 0)
			handshake := parsedProtect.(HandshakePacket)
			headerByte := handshake.ToHeaderByte(handshake)

			// ヘッダ保護を解除する
			unp, tlsinfo = UnprotectHeader(len(headerByte), packet, tlsinfo.KeyBlockTLS13.ServerHandshakeHPKey, true, tlsinfo)
			// ヘッダ保護を解除したパケットをパースする
			parsedUnprotect, plen := ParseLongHeaderPacket(unp, LongHeaderPacketTypeHandshake, false, tlsinfo.QPacketInfo.ServerPacketNumberLength)
			unpHandshake := parsedUnprotect.(HandshakePacket)
			parsedPacket = ParsedQuicPacket{
				// ヘッダ保護を解除したLong Header Packetをパースする
				Packet:     unpHandshake,
				HeaderType: 1,
				PacketType: LongHeaderPacketTypeHandshake,
			}

			// 暗号化するときのOverHeadを足す
			//plen += 16
			// packetを縮める
			packet = packet[plen:]
		// Retry Packet
		case "11":
			parsedRetry, _ := ParseLongHeaderPacket(packet, LongHeaderPacketTypeRetry, true, 0)
			parsedPacket = ParsedQuicPacket{
				Packet:     parsedRetry.(RetryPacket),
				HeaderType: 1,
				PacketType: LongHeaderPacketTypeRetry,
			}
			// packetを縮める
			packet = packet[len(packet):]
		}
	}

	return parsedPacket, packet
}

func ParseLongHeaderPacket(packet []byte, ptype int, protect bool, pnumLen int) (i interface{}, packetLength int) {
	/*
		17.2. Long Header Packets
		Long Header Packet {
		     Header Form (1) = 1,
		     Fixed Bit (1) = 1,
		     Long Packet Type (2),
		     Type-Specific Bits (4),
		     Version (32),
		     Destination Connection ID Length (8),
		     Destination Connection ID (0..160),
		     Source Connection ID Length (8),
		     Source Connection ID (0..160),
		     Type-Specific Payload (..),
		}
	*/
	var long LongHeader
	long.HeaderByte = packet[0:1]
	long.Version = packet[1:5]
	long.DestConnIDLength = packet[5:6]

	offset := 6

	// Destination Connection Lengthが0じゃないならセット
	if !bytes.Equal(long.DestConnIDLength, []byte{0x00}) {
		long.DestConnID = packet[6 : 6+int(long.DestConnIDLength[0])]
		offset += int(long.DestConnIDLength[0])
	}
	long.SourceConnIDLength = packet[offset : offset+1]
	offset++
	// Source Connection Lengthが0じゃないならセット
	if !bytes.Equal(long.SourceConnIDLength, []byte{0x00}) {
		long.SourceConnID = packet[offset : offset+int(long.SourceConnIDLength[0])]
		offset += int(long.SourceConnIDLength[0])
	}

	//Source Connection ID まではLongHeader Typeの各パケットタイプ共通
	switch ptype {
	case LongHeaderPacketTypeInitial:
		var initPacket InitialPacket
		initPacket.LongHeader = long
		// Token Length
		// ないならゼロをセット
		if bytes.Equal(packet[offset:offset+1], []byte{0x00}) {
			initPacket.TokenLength = packet[offset : offset+1]
			offset++
		} else {
			initPacket.TokenLength = packet[offset : offset+2]
			offset += 2
			encodedTokenLength := DecodeVariableInt([]int{int(initPacket.TokenLength[0]), int(initPacket.TokenLength[1])})
			initPacket.Token = packet[offset : offset+int(sumByteArr(encodedTokenLength))]
			offset += int(sumByteArr(encodedTokenLength))
		}
		initPacket.Length = packet[offset : offset+2]
		offset += 2
		if protect {
			// ヘッダ保護を解除しないとPacket Number Lengthがわからないので残り(Packet Number LengthとPayload)をPayloadにそのままセットして返す
			initPacket.Payload = packet[offset:]
		} else {
			decLen := DecodeVariableInt([]int{int(initPacket.Length[0]), int(initPacket.Length[1])})
			packetLength = int(sumByteArr(decLen))
			packetLength += len(initPacket.ToHeaderByte(initPacket))
			switch pnumLen {
			case 1:
				initPacket.PacketNumber = packet[offset : offset+1]
				offset++
				initPacket.Payload = packet[offset:packetLength]
			case 2:
				initPacket.PacketNumber = packet[offset : offset+2]
				offset += 2
				initPacket.Payload = packet[offset:packetLength]
			case 4:
				initPacket.PacketNumber = packet[offset : offset+4]
				offset += 4
				initPacket.Payload = packet[offset:packetLength]
			}
		}
		packetLength -= len(initPacket.ToHeaderByte(initPacket))
		i = initPacket
	case LongHeaderPacketTypeHandshake:
		var handshake HandshakePacket
		handshake.LongHeader = long
		handshake.Length = packet[offset : offset+2]
		offset += 2
		if protect {
			// ヘッダ保護を解除しないとPacket Number Lengthがわからないので残り(Packet Number LengthとPayload)をPayloadにそのままセットして返す
			handshake.Payload = packet[offset:]
		} else {
			decLen := DecodeVariableInt([]int{int(handshake.Length[0]), int(handshake.Length[1])})
			packetLength = int(sumByteArr(decLen))
			packetLength += len(handshake.ToHeaderByte(handshake))
			switch pnumLen {
			case 1:
				handshake.PacketNumber = packet[offset : offset+1]
				offset++
				handshake.Payload = packet[offset:packetLength]
			case 2:
				handshake.PacketNumber = packet[offset : offset+2]
				offset += 2
				handshake.Payload = packet[offset:packetLength]
			case 4:
				handshake.PacketNumber = packet[offset : offset+4]
				offset += 4
				handshake.Payload = packet[offset:packetLength]
			}
		}
		i = handshake
	case LongHeaderPacketTypeRetry:
		var retry RetryPacket
		retry.LongHeader = long
		retryTokenLength := len(packet) - offset - 16
		retry.RetryToken = packet[offset : offset+retryTokenLength]
		offset += retryTokenLength
		retry.RetryIntergrityTag = packet[offset : offset+16]
		i = retry
	}

	return i, packetLength
}

func ParseShortHeaderPacket(packet []byte, pinfo QPacketInfo, protect bool) (short ShortHeader) {
	/*
		17.3. Short Header Packets
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
	var pnumOffset int
	short.HeaderByte = packet[0:1]
	pnumOffset++
	index := bytes.Index(packet, pinfo.DestinationConnID)
	if index != -1 {
		short.DestConnID = packet[index : index+len(pinfo.DestinationConnID)]
		// Packet Number Lengthが始まる位置
		pnumOffset = 1 + len(pinfo.DestinationConnID)
	}

	if protect {
		// ヘッダ保護を解除しないとPacket Number Lengthがわからないので残りをPayloadにそのままセットして返す
		short.Payload = packet[index+len(pinfo.DestinationConnID):]
	} else {
		switch pinfo.ServerPacketNumberLength {
		case 1:
			short.PacketNumber = packet[pnumOffset : pnumOffset+1]
			short.Payload = packet[pnumOffset+1:]
		case 2:
			short.PacketNumber = packet[pnumOffset : pnumOffset+2]
			short.Payload = packet[pnumOffset+2:]
		case 4:
			short.PacketNumber = packet[pnumOffset : pnumOffset+4]
			short.Payload = packet[pnumOffset+4:]
		}
	}

	return short
}

// UnprotectHeader ヘッダ保護を解除したパケットにする
func UnprotectHeader(pnOffset int, packet, hpkey []byte, isLongHeader bool, tlsinfo TLSInfo) ([]byte, TLSInfo) {
	// https://tex2e.github.io/blog/protocol/quic-initial-packet-decrypt
	// RFC9001 5.4.2. ヘッダー保護のサンプル
	// Encrypte Payloadのoffset
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

	// ヘッダ保護を解除したのでPacket Number Lengthを取得する
	pnlength := (packet[0] & 0x03) + 1
	fmt.Printf("packet number length is %d\n", pnlength)
	// Packet Number Lengthを保存
	tlsinfo.QPacketInfo.ServerPacketNumberLength = int(pnlength)

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

	fmt.Printf("unprotected packet is %x\n", packet)

	return packet, tlsinfo
}

// ProtectHeader パケットのヘッダを保護する
func ProtectHeader(pnOffset int, packet, hpkey []byte, isLongHeader bool) []byte {
	// RFC9001 5.4.2. ヘッダー保護のサンプル
	sampleOffset := pnOffset + 4

	fmt.Printf("pnOffset is %d, sampleOffset is %d\n", pnOffset, sampleOffset)
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
	//fmt.Printf("ServerKey is %x, ServerIV is %x\n", keyblock.ServerKey, keyblock.ServerIV)
	block, _ := aes.NewCipher(keyblock.ServerKey)
	aesgcm, _ := cipher.NewGCM(block)
	// IVとxorしたのをnonceにする
	//nonce := getXORNonce(packetnum, keyblock.ClientIV)
	for i, _ := range packetnum {
		packetnum[i] ^= keyblock.ServerIV[i]
	}
	// 復号する
	//fmt.Printf("nonce is %x, add is %x, payload is %x\n", packetnum, header, payload)
	fmt.Printf("nonce is %x, header is %x, payload is %x\n", packetnum, header, payload)
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
			// 次のパケットを読み進める
			packet = packet[5:]
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
				// 次のパケットを読み進める
				packet = packet[4+decodedLength:]
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
				// 次のパケットを読み進める
				packet = packet[5+decodedLength:]
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
			// 次のパケットを読み進める
			packet = packet[4+length+16:]
			i = 0
		case HandShakeDone:
			frame = append(frame, HandshakeDoneFrame{
				Type: packet[0:1],
			})
			// 次のパケットを読み進める
			packet = packet[1:]
			i = 0
		case NewToken:
			token := NewTokenFrame{
				Type: packet[0:1],
			}
			token.TokenLength = packet[1:3]
			decLen := DecodeVariableInt([]int{int(token.TokenLength[0]), int(token.TokenLength[1])})
			tokenLength := int(sumByteArr(decLen))
			token.Token = packet[3 : 3+tokenLength]
			frame = append(frame, token)
			// 次のパケットを読み進める
			packet = packet[3+tokenLength:]
			i = 0
		case Stream:
			stream := StreamFrame{
				Type:       packet[0:1],
				StreamID:   packet[1:2],
				StreamData: packet[2:],
			}
			frame = append(frame, stream)
			// 次のパケットを読み進める
			packet = packet[len(packet):]
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

func NewAckFrame(ackcnt int) ACKFrame {
	return ACKFrame{
		Type:                []byte{(ACK)},
		LargestAcknowledged: []byte{byte(ackcnt)},
		AckDelay:            []byte{0x00},
		AckRangeCount:       []byte{0x00},
		FirstAckRange:       []byte{byte(ackcnt)},
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

func SendQuicPacket(conn *net.UDPConn, packets [][]byte, tlsinfo TLSInfo) (ParsedQuicPacket, []byte) {
	recvBuf := make([]byte, 65535)

	for _, v := range packets {
		conn.Write(v)
	}
	n, _ := conn.Read(recvBuf)

	fmt.Printf("recv packet : %x\n", recvBuf[0:n])

	return ParseRawQuicPacket(recvBuf[0:n], tlsinfo)
}

func ReadNextPacket(conn *net.UDPConn, tlsinfo TLSInfo) (ParsedQuicPacket, []byte) {
	recvBuf := make([]byte, 65535)
	n, _ := conn.Read(recvBuf)
	fmt.Printf("recv packet : %x\n", recvBuf[0:n])

	return ParseRawQuicPacket(recvBuf[0:n], tlsinfo)
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
