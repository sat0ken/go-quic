package main

import (
	"fmt"
	"quic"
)

var localAddr = []byte{127, 0, 0, 1}

func main() {
	initpacket()
	//retrypacket()
}

func initpacket() {
	shello := quic.StrtoByte("010001240303faac906d7be5be01d2f97311acb0f098c3e7dbb661b6987827e007913f35f442000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000d50000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100005000302683300120000002b0003020304003300260024001d002039b2d976219b39efce354d9ac5d4afb52daafd3402e0098fb547fac39007201500390041475f08d68a89670fcc19b00504800800000604800800000704800800000404800c000008010009024064010480007530030245ac0b011a0c000e01040f00200100")
	cryptoFrame := quic.ToPacket(quic.NewQuicCryptoFrame(shello))

	destconnID := quic.StrtoByte("b03b5b77b69a08c92070a495c00e00f9")
	keyblock := quic.CreateQuicInitialSecret(destconnID)
	header, initPacket := quic.NewQuicLongHeader(destconnID, nil, 0, 2)

	paddingLength := 1252 - len(quic.ToPacket(header)) -
		len(initPacket.PacketNumber) - len(cryptoFrame) - 16 - 4

	// ゼロ埋めしてPayloadをセット
	initPacket.Payload = quic.UnshiftPaddingFrame(cryptoFrame, paddingLength)
	//fmt.Printf("paddingLength is %d\n", paddingLength)
	fmt.Printf("After padding payload is %d\n", len(initPacket.Payload))

	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = quic.EncodeVariableInt(length)

	headerByte := quic.ToPacket(header)
	// set Token Length
	headerByte = append(headerByte, 0x00)
	headerByte = append(headerByte, initPacket.Length...)
	headerByte = append(headerByte, initPacket.PacketNumber...)

	fmt.Printf("header is %x\n", headerByte)

	enctext := quic.EncryptQuicPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
	//fmt.Printf("enctext is %x\n", enctext[0:16])

	packet := headerByte
	packet = append(packet, enctext...)

	fmt.Printf("header is %x, %+v\n", quic.ToPacket(header), header)
	protectPacket := quic.ProtectHeader(header, initPacket, packet, keyblock.ClientHeaderProtection)
	// ヘッダとデータで送信するパケットを生成
	fmt.Printf("packet is %x\n", protectPacket)

}

func retrypacket() {
	rawretry := quic.StrtoByte("f00000000100046e19c054938238c63dac3ffe79073d1945aa25d4925e7981e4f5b35488cc6367a9d8de8d3f67fa07d1f601d28f29b408cbdf73e7b8aa0821c46cd9bca7452838dffb9a5e21452fe817b4f7e01bb3546528931dcb812b59161c3d9c2ed3b4ebcb8d04d439f9b1b61decaa08315d4a8d452a0f755bda020e14abc654b2abaf")

	retry, _ := quic.ParseRawQuicPacket(rawretry, true)
	fmt.Printf("%+v\n", retry)

	shello := quic.StrtoByte("010001240303faac906d7be5be01d2f97311acb0f098c3e7dbb661b6987827e007913f35f442000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000d50000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100005000302683300120000002b0003020304003300260024001d002039b2d976219b39efce354d9ac5d4afb52daafd3402e0098fb547fac39007201500390041475f08d68a89670fcc19b00504800800000604800800000704800800000404800c000008010009024064010480007530030245ac0b011a0c000e01040f00200100")
	cryptoFrame := quic.ToPacket(quic.NewQuicCryptoFrame(shello))

	destconnID := quic.StrtoByte("6e19c054")
	keyblock := quic.CreateQuicInitialSecret(destconnID)
	header, initPacket := quic.NewQuicLongHeader(destconnID, nil, 1, 2)

	initPacket.Token = quic.StrtoByte("938238c63dac3ffe79073d1945aa25d4925e7981e4f5b35488cc6367a9d8de8d3f67fa07d1f601d28f29b408cbdf73e7b8aa0821c46cd9bca7452838dffb9a5e21452fe817b4f7e01bb3546528931dcb812b59161c3d9c2ed3b4ebcb8d04d439f9b1b61decaa08315d4a")
	initPacket.TokenLength = quic.EncodeVariableInt(len(initPacket.Token))

	paddingLength := 1252 - len(quic.ToPacket(header)) -
		len(initPacket.PacketNumber) - len(cryptoFrame) - 16 - 4 - len(initPacket.Token) - 1

	// ゼロ埋めしてPayloadをセット
	initPacket.Payload = quic.UnshiftPaddingFrame(cryptoFrame, paddingLength)
	fmt.Printf("After padding payload is %d\n", len(initPacket.Payload))

	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = quic.EncodeVariableInt(length)

	headerByte := quic.ToPacket(header)
	fmt.Printf("header is %x\n", headerByte)
	// c100000001046e19c05400
	//
	// set Token Length
	headerByte = append(headerByte, initPacket.TokenLength...)
	headerByte = append(headerByte, initPacket.Token...)
	headerByte = append(headerByte, initPacket.Length...)
	headerByte = append(headerByte, initPacket.PacketNumber...)

	fmt.Printf("header is %x\n", headerByte)

	enctext := quic.EncryptQuicPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
	_ = enctext

}

// InitalPacketの暗号化
//func sendInitialPacket() interface{} {
//	// sampleのDestination接続ID
//	//destconnID := []byte{0xf2, 0xc0, 0x28, 0xbb, 0x71, 0x53, 0x35, 0x74, 0x0e, 0xc0, 0x1d, 0xe2, 0x4d, 0x74}
//	destconnID := []byte{
//		0xf7, 0x02, 0x02, 0xff, 0x24, 0x9a, 0xe1, 0x0d,
//		0xeb, 0x76, 0xc9, 0xb7, 0xe5, 0x85, 0x88, 0xc0,
//	}
//	sourceconnID := []byte{
//		0x74, 0xcf, 0xe6, 0x47, 0x10, 0x1c, 0xc7, 0x8f,
//	}
//	//destconnID := tcpip.RandomByte(16)
//	keyblock := quic.CreateQuicInitialSecret(destconnID)
//	// A.2. クライアントの初期 Crypto Frame
//	// RFC9001のsample
//	// plaintext := tcpip.StrtoByte("060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff")
//	// plaintext := tcpip.StrtoByte("010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff")
//	// payloadを作る
//	var clienthello quic.ClientHello
//	tlsinfo, clientHelloPacket := clienthello.NewQuicClientHello(sourceconnID, []byte("localhost"))
//	_ = tlsinfo
//
//	crypto := quic.NewQuicCryptoFrame(clientHelloPacket)
//	cryptoByte := quic.ToPacket(crypto)
//	//fmt.Printf("crypto frame is %x\n", cryptoByte)
//
//	header, initPacket := quic.NewQuicLongHeader(destconnID, sourceconnID, 0, 4)
//
//	// Clientが送信するInitial Packetを含むUDPペイロードは1200バイト以上にしないといけない
//	// PADDINGフレームの長さを計算する
//	//paddingLength := 1200 - 5 - len(initPacket.PacketNumber) -
//	//	len(header.SourceConnID) - len(initPacket.Token) -
//	//	16 - 2 - len(plaintext) - 16
//	paddingLength := 1252 - len(quic.ToPacket(header)) -
//		len(initPacket.PacketNumber) - len(cryptoByte) - 16 - 4
//	//fmt.Printf("header is %d, pnum len is %d, payload len is %d\n", len(tcpip.ToPacket(header)),
//	//	4, 322)
//
//	// ゼロ埋めしてPayloadをセット
//	initPacket.Payload = quic.AppendPaddingFrame(cryptoByte, paddingLength)
//	//fmt.Printf("paddingLength is %d, %d\n", paddingLength, len(initPacket.Payload))
//	//fmt.Printf("After padding payload is %x\n", initPacket.Payload)
//
//	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
//	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
//	// 可変長整数のエンコードをしてLengthをセット
//	initPacket.Length = quic.EncodeVariableInt(length)
//
//	headerByte := quic.ToPacket(header)
//	// set Token Length
//	headerByte = append(headerByte, 0x00)
//	headerByte = append(headerByte, initPacket.Length...)
//	headerByte = append(headerByte, initPacket.PacketNumber...)
//
//	fmt.Printf("header is %x\n", headerByte)
//	////fmt.Printf("payload is %x\n", initPacket.Payload)
//	//
//	////add := tcpip.StrtoByte("c300000001088394c8f03e5157080000449e00000002")
//	enctext := quic.EncryptQuicPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
//	////enctext := tcpip.StrtoByte("ce906282754a91d7f16f3df14e085f5d9e4d50cd52874d4579bfe111b46500a245923f9a403c409bfd097338edb5902463d734f8454ac4520fa029c3078b4961343d31d988fd1f3bcea895a66f06bbcfabedf43abc080c5435c2c49792663f5272b31516258ce6fc1acd4899452b59ed528759371206a7b475788c0f451ca40049e03913816bde29ca1b6f5f565f404e07d06e6a55f363604e5e9c4f08b65ae4ae61aa9d776d2ff91e2031ec6012a90a3994d008d160fcdbeca2d10677ebbf372ff9e5601146b50c0a3d467c3b90a513a8916ace72d66faca85061de95e421d34dc214335d055bdc18bec56b3c6501f350da0a1f071449f940e68edc538320fdff0e140d01073ea22ac2f37f514049dd961f12ec7a7a18226eb063c45fcd9c6240d2c036f62f3a0ab9be59bc83f9325bae314c910ce41d46f048ea8ed71e7f136c3f9cbc16bbf82b0c83df3cd331025e879fdb4bf45c53c89ba48c8a67c052ca32a9f2d23f188ac58ad488f5da4d3373fbff97d731a9735667c0c82c0a365d72545a3cf2f46eb60c12f8e8b3218c38865d4fabce2614b1bb2b918913034c8bcf79670aa6f315e6799eacaa457fa934a402dafab7d59dceaea0125ba5d7b8b24b6e913512b160ef22a89892574682ff679c10da6d203aadd352000716079402b7c6331778871ec56deb6d3eda1023ec358bbe211dee796653230c3fbc8d2477fc94360649af5cb00c1674876c2e9e66f9935d722d4d759413c54da0a7046b651dace9c579512caedd26f13129982228571873a16ce2d7a1457562219bc170d202ed8f7047681be7b5a7d544414d9934286f5ff228c057dc685089c7f31ae768c69f625e6b3828976105d53dd07e0f5d7f537bdb4a58ffca39d303b36f7a8ef8ca7e0f68a632cef6d93886e0f9c213e926b948361b1bb0aa3a04c1e012990da08dec35219864192a705c15f6d27aa88faa0b6be6921f4be6e8ab9a3dc1d72288c210ba74c69336618d52a8581e9c4acd9c86871fa8836434f786b06dff4624e508d6cbd35f638d65a54910a284ec7f2ee27f786d20a439c34c7f6b7fcc5d4cd9d7f162a6ca021a2dfde25f37a2e33a3b785b46a41e7324bd5aa180ef0b97541bd74b1297544dbc64c2f7251aa4a75709536d22bb300281708c1ffb30eb40ee9204be8ef5fe396d9e21fec4c6aab00216cd5ef83e2ccf0aefba5a02a958d94768799cdfc45eb4d4c0e9fa02afb43092f9325100640d7d98bcfa11ba7547f4b94fcbe9c350df274549e469900c11069a0fd83fdc3d5b03ca82657d0e3364461217023250fb3d379b2128ce485e8108c1c0cec66f534e3fc714771060af27f8b0909ac31c3ea658a25b438a8fb66f70769f22c1948a2bc5f306dc1a32c8e784b3496f720c4b9d14ef90ca46a82e8975a2c0654cc71442b0f86c66608eb4ecf8a1b191b9264e75a236be2b29ebae6513fa522a9a8f02d5a8f2281fe4fa343efd00b589c388b3bab6762b53201b0d6cc55aa13d812117839236df7ee7c8775c8e3f44db32a547d3427f1c4f13fa43640a46bbc0f121fe86cbc5f9a1fc69240cdc0b0f1dfa6d404804cfac849255a78454db3f5d9b723ffb46c5270f9b0ec7b61a5813c69a43ee29ea905eb0eabf3185bc14bfc95282acbc0a4e0999f454d36e366c14ca9665316c471ff4b6fcb884ed66f95150b1ff09cc1818d77ebeda98388cfd1b96c7bc250811803b2b2952d00d")
//	fmt.Printf("enctext is %x\n", enctext[0:16])
//	//
//	protectHeader := quic.QuicHeaderToProtect(headerByte, enctext[0:16], keyblock.ClientHeaderProtection)
//	fmt.Printf("protected header is %x\n", protectHeader)
//
//	//ヘッダとデータで送信するパケットを生成
//	packet := protectHeader
//	packet = append(packet, enctext...)
//
//	recvPacket := quic.SendQuicPacket(packet, []byte{127, 0, 0, 1}, 18443)
//	//retry := recvPacket.QuicFrames[0].(tcpip.RetryPacket)
//
//	return recvPacket
//}

//func _() {
//	// Initial
//	quicInfo := sendInitialPacket()
//
//	// 以下でRetry TokenをセットしてInitial Packetを送信し直す
//	destconnID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
//	keyblock := tcpip.CreateQuicInitialSecret(destconnID)
//	quicpacket := tcpip.NewQuicLongHeader(destconnID, 1, 4)
//
//	header := quicpacket.QuicHeader.(tcpip.QuicLongCommonHeader)
//	initPacket := quicpacket.QuicFrames[0].(tcpip.InitialPacket)
//	initPacket.Token = quicInfo.RetryToken
//	initPacket.TokenLength = tcpip.EncodeVariableInt(len(initPacket.Token))
//
//	//fmt.Printf("initPacket is %d\n", len(initPacket.Token))
//
//	//paddingLength := 1200 - 5 - len(initPacket.PacketNumber) -
//	//	len(header.SourceConnID) - len(initPacket.Token) -
//	//	16 - 2 - len(quicInfo.ClientHello) - 16
//	//current := len(tcpip.ToPacket(header)) + len(initPacket.PacketNumber) + len(initPacket.Token) + len(quicInfo.ClientHello) + 16 + 2
//	//fmt.Printf("current length is %+v\n", current)
//
//	paddingLength := 1200 - len(tcpip.ToPacket(header)) -
//		len(initPacket.PacketNumber) - len(quicInfo.ClientHello) - len(initPacket.Token) - 16 - 2
//	fmt.Printf("header is %+v\n", header)
//	//fmt.Printf("padding length is %d, clienthello is %d\n", paddingLength, len(quicInfo.ClientHello))
//
//	// ゼロ埋めしてPayloadをセット
//	initPacket.Payload = tcpip.AddPaddingFrame(quicInfo.ClientHello, paddingLength)
//	//fmt.Printf("After padding payload is %x\n", initPacket.Payload)
//
//	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
//	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
//	// 可変長整数のエンコードをしてLengthをセット
//	initPacket.Length = tcpip.EncodeVariableInt(length)
//
//	headerByte := tcpip.ToPacket(header)
//	// Source Connection ID Lengthの0を入れる
//	//headerByte = append(headerByte, 0x00)
//	headerByte = append(headerByte, initPacket.TokenLength...)
//	headerByte = append(headerByte, initPacket.Token...)
//	headerByte = append(headerByte, initPacket.Length...)
//	headerByte = append(headerByte, initPacket.PacketNumber...)
//
//	enctext := tcpip.EncryptQuicPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
//	fmt.Printf("headerByte is %x\n", headerByte)
//	protectHeader := tcpip.QuicHeaderToProtect(headerByte, enctext[0:16], keyblock.ClientHeaderProtection)
//
//	//ヘッダとデータで送信するパケットを生成
//	packet := protectHeader
//	packet = append(packet, enctext...)
//	fmt.Printf("packet length is %d\n", len(packet))
//
//	tcpip.SendQuicPacket(packet, 42237, 18443)
//
//}
