package main

import (
	"fmt"
	"quic"
)

var localAddr = []byte{127, 0, 0, 1}

const port = 18443

func main() {
	var tlsinfo quic.TLSInfo
	var init quic.InitialPacket
	var packet, retryInit []byte

	tlsinfo.QPacketInfo = quic.QPacketInfo{
		DestinationConnID:        quic.StrtoByte("7b268ba2b1ced2e48ed34a0a38"),
		SourceConnID:             nil,
		Token:                    nil,
		InitialPacketNumber:      0,
		ClientPacketNumberLength: 2,
		CryptoFrameOffset:        0,
	}

	tlsinfo, packet = init.CreateInitialPacket(tlsinfo)

	conn := quic.ConnectQuicServer(localAddr, port)
	parsed, recvPacket := quic.SendQuicPacket(conn, [][]byte{packet}, tlsinfo)
	if len(recvPacket) == 0 {
		fmt.Println("all packet is parsed")
	}

	// Packet NumberをIncrementする
	tlsinfo.QPacketInfo.InitialPacketNumber++
	retryPacket := parsed.Packet.(quic.RetryPacket)

	// ServerからのRetryパケットのSource Connection IDをDestination Connection IDとしてInitial Packetを生成する
	tlsinfo.QPacketInfo.DestinationConnID = retryPacket.LongHeader.SourceConnID
	tlsinfo.QPacketInfo.Token = retryPacket.RetryToken

	tlsinfo, retryInit = init.CreateInitialPacket(tlsinfo)

	// ここでInitial PacketでServerHelloが、Handshake PacketでCertificateの途中まで返ってくる
	// recvhandshake[0]にInitial Packet(Server hello), [1]にHandshake Packet(Certificate~)
	parsed, recvPacket = quic.SendQuicPacket(conn, [][]byte{retryInit}, tlsinfo)

	// Initial packet を処理する
	recvInitPacket := parsed.Packet.(quic.InitialPacket)
	// Packetを復号化してFrameにパースする、[0]にはAck 、[1]にはCryptoが入る
	qframes := recvInitPacket.ToPlainQuicPacket(recvInitPacket, tlsinfo)
	//Initial Packetを送り返すときには受信したSourceConnIDをDestinationConnectionIDにセットする
	tlsinfo.QPacketInfo.DestinationConnID = recvInitPacket.LongHeader.SourceConnID

	var shello quic.ServerHello
	tlsPackets, isfrag := quic.ParseTLSHandshake(qframes[1].(quic.CryptoFrame).Data)
	if !isfrag {
		shello = tlsPackets[0].(quic.ServerHello)
		fmt.Printf("Server Hello is %+v\n", shello)
	}
	commonkey := quic.GenerateCommonKey(shello.TLSExtensions, tlsinfo.ECDHEKeys.PrivateKey)

	// ServerHelloのパケットを追加
	tlsinfo.HandshakeMessages = append(tlsinfo.HandshakeMessages, qframes[1].(quic.CryptoFrame).Data...)

	// 鍵導出を実行
	tlsinfo.KeyBlockTLS13 = quic.KeyscheduleToMasterSecret(commonkey, tlsinfo.HandshakeMessages)

	// Handshake Packetを処理(Crypto Frame(ServerCertificateの途中まで)
	fmt.Printf("remain packet is %x\n", recvPacket)
	parsed, recvPacket = quic.ParseRawQuicPacket(recvPacket, tlsinfo)
	var handshake quic.HandshakePacket
	if len(recvPacket) == 0 {
		handshake = parsed.Packet.(quic.HandshakePacket)
	}

	frames := handshake.ToPlainQuicPacket(handshake, tlsinfo)
	tlsPackets, frag := quic.ParseTLSHandshake(frames[0].(quic.CryptoFrame).Data)

	var fragPacket quic.ParsedQuicPacket
	// パケットが途中で途切れてるなら次のパケットを読み込む
	// packetがfragmentだった場合、Crypto FrameのOffsetが1つ前のCrypto FrameのLengthになる。というのもPayloadは前のCrypto Frameの続きであるから
	if frag {
		// [0]にTLSパケットの続き(Certificate, CertificateVerify, Finished)
		// [1]にShort HeaderのNew Connection ID Frameが3つ
		fragPacket, recvPacket = quic.ReadNextPacket(conn, tlsinfo)
		tlsinfo.QPacketInfo.CryptoFrameOffset = quic.SumLengthByte(frames[0].(quic.CryptoFrame).Length)
	}

	fraghs := fragPacket.Packet.(quic.HandshakePacket)
	fragedhsframe := fraghs.ToPlainQuicPacket(fraghs, tlsinfo)
	// 1つ前のCrypto Frameの途中までのデータに続きのデータをくっつける
	tlsCertificate := frames[0].(quic.CryptoFrame).Data
	tlsCertificate = append(tlsCertificate, fragedhsframe[0].(quic.CryptoFrame).Data...)

	tlspacket, frag := quic.ParseTLSHandshake(tlsCertificate)
	if !frag {
		_ = tlspacket
		//fmt.Printf("parsed tls packet is %+v\n", tlspacket)
	}

	// ClientHello, ServerHello, EncryptedExtension, ServerCertificate, CertificateVerify, Fnished
	tlsinfo.HandshakeMessages = append(tlsinfo.HandshakeMessages, tlsCertificate...)
	// Application用の鍵導出を行う
	tlsinfo = quic.KeyscheduleToAppTraffic(tlsinfo)
	tlsinfo.QPacketInfo.DestinationConnIDLength = fraghs.LongHeader.DestConnIDLength

	// 残りはShortHeader Packet
	fmt.Printf("remain packet is %x\n", recvPacket)
	parsed, recvPacket = quic.ParseRawQuicPacket(recvPacket, tlsinfo)
	var short quic.ShortHeader
	if len(recvPacket) == 0 {
		fmt.Println("all packet is parsed")
		short = parsed.Packet.(quic.ShortHeader)
	}
	frames = short.ToPlainQuicPacket(short, tlsinfo)
	fmt.Printf("NewConnectionID is %+v\n", frames[0])

	tlsinfo.QPacketInfo.InitialPacketNumber++
	ack := init.CreateInitialAckPacket(tlsinfo)
	var tlsfin quic.HandshakePacket
	finpacket := tlsfin.CreateHandshakePacket(tlsinfo)

	// Finishedを送りHandshake_Doneを受信
	parsed, recvPacket = quic.SendQuicPacket(conn, [][]byte{ack, finpacket}, tlsinfo)
	if len(recvPacket) == 0 {
		fmt.Println("all packet is parsed")
		tlsfin = parsed.Packet.(quic.HandshakePacket)
	}

	fmt.Printf("recv parsed packet is %x\n", tlsfin)

	//var short quic.ShortHeader
	shortByte := short.CreateShortHeaderPacket(tlsinfo, quic.NewControlStream())
	tlsinfo.QPacketInfo.ShortHeaderPacketNumber++

	parsed, recvPacket = quic.SendQuicPacket(conn, [][]byte{shortByte}, tlsinfo)
	//fmt.Printf("recv http3 setting packet is %x\n", recvPacket)
	if len(recvPacket) == 0 {
		fmt.Println("all packet is parsed")
		short = parsed.Packet.(quic.ShortHeader)
	}
	frames = short.ToPlainQuicPacket(short, tlsinfo)
	for _, v := range frames {
		fmt.Printf("frames is %+v\n", v)
	}

	h3request := short.CreateShortHeaderPacket(tlsinfo, quic.NewHttp3Request())
	parsed, recvPacket = quic.SendQuicPacket(conn, [][]byte{h3request}, tlsinfo)
	if len(recvPacket) == 0 {
		fmt.Println("all packet is parsed")
		short = parsed.Packet.(quic.ShortHeader)
	}
	frames = short.ToPlainQuicPacket(short, tlsinfo)
	for _, v := range frames {
		fmt.Printf("frames is %+v\n", v)
	}

	parsed, recvPacket = quic.ReadNextPacket(conn, tlsinfo)
	if len(recvPacket) == 0 {
		fmt.Println("all packet is parsed")
		short = parsed.Packet.(quic.ShortHeader)
	}
	frames = short.ToPlainQuicPacket(short, tlsinfo)
	for _, v := range frames {
		fmt.Printf("HTTP3 Header frames is %+v\n", v)
	}
	stream := frames[1].(quic.StreamFrame)
	fmt.Printf("frame %+v\n\n", stream)

	h3data := quic.ParseHTTP3(stream.StreamData)
	fmt.Printf("message from server : %s\n", h3data[1].Payload)
}
