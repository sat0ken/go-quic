package quic

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
)

func NewQuicClientHello() (ecdheKey ECDHEKeys, clientHelloPacket []byte) {

	handshake := ClientHello{
		HandshakeType:   []byte{HandshakeTypeClientHello},
		Length:          []byte{0x00, 0x00, 0x00},
		Version:         TLS1_2,
		Random:          noRandomByte(32),
		SessionIDLength: []byte{0x00},
		//CipherSuitesLength: []byte{0x00, 0x06},
		// TLS_RSA_WITH_AES_128_GCM_SHA256
		// TLS_RSA_WITH_AES_128_GCM_SHA384
		// TLS_CHACHA20_POLY1305_SHA256
		//CipherSuites: []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03},

		// quic-goのCipherSuite
		CipherSuitesLength: []byte{0x00, 0x26},
		CipherSuites: []byte{
			0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
			0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x09, 0xc0, 0x13,
			0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d,
			0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a,
			0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
		},
		CompressionLength: []byte{0x01},
		CompressionMethod: []byte{0x00},
	}

	// TLS1.3のextensionをセット
	handshake.Extensions, ecdheKey = setQuicTLSExtension()
	// Quic transport parameterを追加
	handshake.Extensions = append(handshake.Extensions, setQuicTransportParameters()...)
	// ExtensionLengthをセット
	handshake.ExtensionLength = UintTo2byte(uint16(len(handshake.Extensions)))

	// Typeの1byteとLengthの3byteを合計から引く
	handshake.Length = UintTo3byte(uint32(toByteLen(handshake) - 4))
	// byteにする
	clientHelloPacket = toByteArr(handshake)

	//var hello []byte
	//hello = append(hello, NewTLSRecordHeader("Handshake", toByteLen(handshake))...)
	//hello = append(hello, handshakebyte...)

	// ClientHelloを保存しておく
	//tlsinfo.HandshakeMessages = handshakebyte

	return ecdheKey, clientHelloPacket
}

// quic-goが送っていたのをセットする
func setQuicTransportParameters() []byte {
	var quicParams []byte
	var quicParamsBytes []byte

	// GREASE Bit
	quicParams = append(quicParams, []byte{0x42, 0x0b, 0x04, 0x1f, 0xad, 0x78, 0x8e}...)
	quicParams = append(quicParams, initialMaxStreamDataBidiLocalParamByte...)
	quicParams = append(quicParams, initialMaxStreamDataBidiRemoteParamByte...)
	quicParams = append(quicParams, initialMaxStreamDataUniParamByte...)
	quicParams = append(quicParams, initialMaxDataParamByte...)
	quicParams = append(quicParams, initialMaxStreamsBidiParamByte...)
	quicParams = append(quicParams, initialMaxStreamsUniParamByte...)
	quicParams = append(quicParams, maxIdleTimeoutParamByte...)
	quicParams = append(quicParams, maxUdpPayloadSizeParamByte...)
	// GREASE Bit
	quicParams = append(quicParams, []byte{0x0b, 0x01, 0x1a}...)
	quicParams = append(quicParams, disableActiveMigrationParamByte...)
	quicParams = append(quicParams, activeConnectionIdLimitParamByte...)

	// Set source connection id Length
	//initialSourceConnectionId = append(initialSourceConnectionId, byte(len(sourceConnID)))
	// Set source connection id
	//initialSourceConnectionId = append(initialSourceConnectionId, sourceConnID...)

	quicParams = append(quicParams, initialSourceConnectionIdParamByte...)
	quicParams = append(quicParams, maxDatagramFrameSizeParamByte...)

	// tls extensionのType = 57 をセット
	quicParamsBytes = append(quicParamsBytes, []byte{0x00, 0x39}...)
	// Lengthをセット
	quicParamsBytes = append(quicParamsBytes, UintTo2byte(uint16(len(quicParams)))...)
	quicParamsBytes = append(quicParamsBytes, quicParams...)

	return quicParamsBytes
}

// golangのclientのをキャプチャしてそのままセットする
func setQuicTLSExtension() ([]byte, ECDHEKeys) {
	var tlsExtension []byte

	// server_name
	tlsExtension = append(tlsExtension, setServerNameExt([]byte(`localhost`))...)

	//　status_reqeust
	tlsExtension = append(tlsExtension, []byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00}...)

	// supported_groups
	tlsExtension = append(tlsExtension, []byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d,
		0x00, 0x17, 0x00, 0x18, 0x00, 0x19}...)

	// ec_point_formats
	tlsExtension = append(tlsExtension, []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}...)

	// signature_algorithms
	tlsExtension = append(tlsExtension, []byte{
		0x00, 0x0d, 0x00, 0x1a, 0x00, 0x18, 0x08, 0x04,
		0x04, 0x03, 0x08, 0x07, 0x08, 0x05, 0x08, 0x06,
		0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x05, 0x03,
		0x06, 0x03, 0x02, 0x01, 0x02, 0x03,
	}...)

	// renagotiation_info
	tlsExtension = append(tlsExtension, []byte{0xff, 0x01, 0x00, 0x01, 0x00}...)

	// Application Layer Protocol Negotiation
	//tlsExtension = append(tlsExtension, []byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33}...)
	// quic-echo-example
	tlsExtension = append(tlsExtension, []byte{
		0x00, 0x10, 0x00, 0x14, 0x00, 0x12, 0x11, 0x71,
		0x75, 0x69, 0x63, 0x2d, 0x65, 0x63, 0x68, 0x6f,
		0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65}...)

	// signed_certificate_timestamp
	tlsExtension = append(tlsExtension, []byte{0x00, 0x12, 0x00, 0x00}...)

	// supported_versions
	tlsExtension = append(tlsExtension, []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}...)

	// 共通鍵を生成する
	clientkey := genrateClientECDHEKey()

	// key_share, DHEの公開鍵を送る
	// Type=0x0033, Length=0x0026, ClientKeyShareLength=0x0024
	tlsExtension = append(tlsExtension, []byte{0x00, 0x33, 0x00, 0x26, 0x00, 0x24}...)
	// Group=0x001d
	tlsExtension = append(tlsExtension, UintTo2byte(uint16(tls.X25519))...)
	// keyのLength = 32byte
	tlsExtension = append(tlsExtension, []byte{0x00, 0x20}...)
	// 公開鍵を追加()
	tlsExtension = append(tlsExtension, clientkey.PublicKey...)
	//tlsExtension = append(tlsExtension, strtoByte("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")...)

	// set length
	//tlsExtensionByte = append(tlsExtensionByte, UintTo2byte(uint16(len(tlsExtension)))...)
	//tlsExtensionByte = append(tlsExtensionByte, tlsExtension...)

	return tlsExtension, clientkey
}

func ParseTLSHandshake(packet []byte) ([]interface{}, bool) {
	var handshake []interface{}

	for i := 0; i < len(packet); i++ {
		switch packet[0] {
		case HandshakeTypeServerHello:
			hello := ServerHello{
				HandshakeType:     packet[0:1],
				Length:            packet[1:4],
				Version:           packet[4:6],
				Random:            packet[6:38],
				SessionIDLength:   packet[38:39],
				CipherSuites:      packet[39:41],
				CompressionMethod: packet[41:42],
				ExtensionLength:   packet[42:44],
				TLSExtensions:     ParseTLSExtensions(packet[44:]),
			}
			handshake = append(handshake, hello)
			// packetを縮める, TLSレコードヘッダの4byte+Length
			packet = packet[4+sum3BytetoLength(hello.Length):]
			i = 0
		case HandshakeTypeEncryptedExtensions:
			encExt := EncryptedExtensions{
				HandshakeType:   packet[0:1],
				Length:          packet[1:4],
				ExtensionLength: packet[4:6],
				TLSExtensions:   ParseTLSExtensions(packet[6:]),
			}
			handshake = append(handshake, encExt)
			// packetを縮める, TLSレコードヘッダの4byte+Length
			packet = packet[4+sum3BytetoLength(encExt.Length):]
			i = 0
		case HandshakeTypeCertificate:
			cert := ServerCertificate{
				HandshakeType:                    packet[0:1],
				Length:                           packet[1:4],
				CertificatesRequestContextLength: packet[4:5],
				CertificatesLength:               packet[5:8],
			}

			// Certificate PacketのLengthよりPacketの残りのLengthが小さいときはTLSパケットが分割されてるので、
			// 読み込みをやめて前半のパケットを保存しておく
			if len(packet) < int(sum3BytetoLength(cert.Length)) {
				fragPacket := FragmentTLSPacket{
					Type:   HandshakeTypeCertificate,
					Packet: packet[:],
					// 残りのPacketのLength, 最後に足している4byteはTLSレコードヘッダの4byte(Typeの1byte + Lengthの3byte)
					RemainPacketLength: int(sum3BytetoLength(cert.Length)) - len(packet) + 4,
				}
				handshake = append(handshake, fragPacket)
				// packetを縮める
				packet = packet[len(packet):]
				i = 0
			} else {
				cert.Certificates = readCertificates(packet[8:])
				handshake = append(handshake, cert)
				// packetを縮める
				packet = packet[4+sum3BytetoLength(cert.Length):]
				i = 0
			}
		case HandshakeTypeCertificateVerify:
			verify := CertificateVerify{
				HandshakeType:           packet[0:1],
				Length:                  packet[1:4],
				SignatureHashAlgorithms: packet[4:6],
				SignatureLength:         packet[6:8],
				Signature:               packet[8:],
			}
			handshake = append(handshake, verify)
			// packetを縮める, TLSレコードヘッダの4byte+Length
			packet = packet[4+sum3BytetoLength(verify.Length):]
			i = 0
		case HandshakeTypeFinished:
			finish := FinishedMessage{
				HandshakeType: packet[0:1],
				Length:        packet[1:4],
				VerifyData:    packet[4:],
			}
			handshake = append(handshake, finish)
			// packetを縮める, TLSレコードヘッダの4byte+Length
			packet = packet[4+sum3BytetoLength(finish.Length):]
			i = 0
		case HandshakeTypeNewSessionTicket:
			ticketLength := binary.BigEndian.Uint16(packet[21:23]) + 23
			session := SessionTicket{
				HandshakeType:     packet[0:1],
				Length:            packet[1:4],
				TicketLifeTime:    packet[4:8],
				TicketAgeAdd:      packet[8:12],
				TicketNonceLength: packet[12:13],
				TicketNonce:       packet[13:21],
				TicketLength:      packet[21:23],
				Ticket:            packet[23:ticketLength],
				TicketExtensions:  packet[ticketLength:],
			}
			handshake = append(handshake, session)
			// packetを縮める, TLSレコードヘッダの4byte+Length
			packet = packet[4+sum3BytetoLength(session.Length):]
			i = 0
		}
	}

	return handshake, isPacketFragment(handshake)
}

func setServerNameExt(hostname []byte) []byte {
	sname := ServerNameIndicationExtension{
		ServerNameListLength: UintTo2byte(uint16(len(hostname) + 3)),
		ServerNameType:       []byte{0x00},
		ServerNameLength:     UintTo2byte(uint16(len(hostname))),
		ServerName:           hostname,
	}

	// type
	extbyte := []byte{0x00, 0x00}
	// set packet length
	extbyte = append(extbyte, UintTo2byte(toByteLen(sname))...)
	extbyte = append(extbyte, toByteArr(sname)...)

	return extbyte
}

func ParseTLSExtensions(extPacket []byte) (tlsEx []TLSExtensions) {
	for i := 0; i < len(extPacket); i++ {
		switch extPacket[1] {
		case TLSExtSupportedVersions:
			tlsEx = append(tlsEx, TLSExtensions{
				Type:   extPacket[0:2],
				Length: extPacket[2:4],
				Value: SupportedVersions{
					Version: extPacket[4:6],
				},
			})
			// packetを縮める
			extPacket = extPacket[6:]
			i = 0
		case TLSExtKeyShare:
			tlsEx = append(tlsEx, TLSExtensions{
				Type:   extPacket[0:2],
				Length: extPacket[2:4],
				Value: KeyShareExtension{
					Group:             extPacket[4:6],
					KeyExchangeLength: extPacket[6:8],
					KeyExchange:       extPacket[8:40],
				},
			})
			// packetを縮める
			extPacket = extPacket[40:]
			i = 0
		case TLSExtALPN:
			alpnExt := TLSExtensions{
				Type:   extPacket[0:2],
				Length: extPacket[2:4],
			}
			alpn := ALPNProtocol{
				ALPNExtLength: extPacket[4:6],
				StringLength:  extPacket[6:7],
			}
			alpn.NextProtocol = extPacket[7 : 7+alpn.StringLength[0]]
			alpnExt.Value = alpn
			tlsEx = append(tlsEx, alpnExt)
			// packetを縮める
			extPacket = extPacket[7+alpn.StringLength[0]:]
			i = 0
		case TLSExtQuicTP:
			quicTps := TLSExtensions{
				Type:   extPacket[0:2],
				Length: extPacket[2:4],
			}
			quicTps.Value = ParseQuicTransportPrameters(extPacket[4 : 4+sumByteArr(quicTps.Length)])
			tlsEx = append(tlsEx, quicTps)
			// packetを縮める
			extPacket = extPacket[4+sumByteArr(quicTps.Length):]
			i = 0
		}
	}
	return tlsEx
}

func checkQuicTransportPram(id byte) bool {
	for _, v := range quicTransportPrameterMaps {
		if int(id) == v {
			//fmt.Printf("quic transport parameter type is %s\n", k)
			return true
		}
	}
	return false
}

func ParseQuicTransportPrameters(packet []byte) (quicPrams []QuicParameters) {

	for i := 0; i < len(packet); i++ {
		if checkQuicTransportPram(packet[0]) {
			param := QuicParameters{
				Type:   packet[0:1],
				Length: packet[1:2],
			}
			param.Value = packet[2 : 2+param.Length[0]]
			quicPrams = append(quicPrams, param)
			// packetを縮める
			packet = packet[2+int(param.Length[0]):]
			i = 0
		} else {
			// GREASEを処理する
			// typeで定義されてなければGREASEとみなす（面倒くさいから）
			// https://datatracker.ietf.org/doc/html/draft-ietf-quic-bit-grease#section-3
			// The QUIC Bit is defined as the second-to-most significant bit of the first
			// byte of QUIC packets (that is, the value 0x40).
			// と書いてあるから0byte目が0x40以上ならGREASEと判断し、可変長整数デコードしてチェックするのが正しそう？（面倒くさい）
			param := QuicParameters{
				Type:   packet[0:2],
				Length: packet[2:3],
			}
			param.Value = packet[3 : 3+param.Length[0]]
			quicPrams = append(quicPrams, param)
			// packetを縮める
			packet = packet[3+int(param.Length[0]):]
			i = 0
		}
	}
	return quicPrams
}

func isPacketFragment(packet []interface{}) bool {
	for _, v := range packet {
		t := fmt.Sprintf("%T", v)
		if t == "quic.FragmentTLSPacket" {
			return true
		}
	}
	return false
}
