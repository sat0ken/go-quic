package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"log"
	"quic"
)

func main() {
	p := quic.StrtoByte("0000508ba0e41d139d09b8179a699fd1c1d75f10839bd9ab5f508bed6988b4c7531efdfad867")
	//p := quic.StrtoByte("568ba0e41d139d09b8179a699f")
	//p := quic.StrtoByte("0000508b089d5c0b8170dc081a699fd1c1d75f10839bd9ab5f508bed6988b4c7531efdfad867")
	//p := quic.StrtoByte("0000508798e79a82ae43d3d1c1d75f10839bd9ab5f508bed6988b4c7531efdfad867")
	headers := quic.DecodeHttp3Header(p)

	for _, v := range headers {
		fmt.Printf("Header Name is %s, Value is %s\n", v.Name, v.Value)
	}

	header := quic.CreateHttp3Header(":method", "localhost:18443")
	header = append(header, quic.CreateHttp3Header("access-control-request-headers", "content-type")...)
	//header = append(header, quic.CreateHttp3Header(":status", "204")...)
	//header = append(header, quic.CreateHttp3Header("early-data", "1")...)
	//header = append(header, quic.CreateHttp3Header("age", "0")...)
	//header = append(header, quic.CreateHttp3Header("forwarded", "")...)
	//header = append(header, quic.CreateHttp3Header("content-encoding", "br")...)
	//header = append(header, quic.CreateHttp3Header(":method", "quic-go HTTP/3")...)

	fmt.Printf("header OK %x\n", p)
	fmt.Printf("header OK 0000%x\n", header)

	fmt.Printf("huffman is %s\n", quic.HuffmanDecode(quic.StrtoByte("a0e41d139d09b8179a699f")))
	fmt.Printf("huffman is %x\n", quic.HuffmanEncode("localhost:18443"))

}

func _() {
	var tlsinfo quic.TLSInfo
	chello := quic.StrtoByte("0100013003030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000e10000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100014001211717569632d6563686f2d6578616d706c6500120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b740039003e420b041fad788e0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00200100")
	serverHello := quic.StrtoByte("020000560303000000000000000000000000000000000000000000000000000000000000000000130100002e002b0002030400330024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")
	encryptedExtensions := quic.StrtoByte("08000090008e00100014001211717569632d6563686f2d6578616d706c650039007241ae0dff4c11f1b2cd93f99dc5cea1cc0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c0002101ae14003acb9d4c32fb8ab4ea68e7693000d7b268ba2b1ced2e48ed34a0a380e01040f044a4b30eb10045306bcce200100")
	serverCertificate := quic.StrtoByte("0b0004240000042000041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee0000")
	certificateVerify := quic.StrtoByte("0f00010408040100b9e4e4195c38fa814824567a0a3a5dbf667c93eb0ac0825d329d2bed57fa473817c47e811b3e803ba8020582ec67fe30d47f06b464e89684f064a0829272162cee7e2e2c692ffbade10bf8708ab6faf6bf5315ae2b200b9aac82d99e7e0dd473ee4ba2593490c4c27bc9caa9033e4e856018ab070d13d7eaca63c2b7a91a2f7d7ab2fef50d4d26fbc53d690c1fbc8ce8131215ccffba292cfcb4072f2a148ec036f0f72a32e16088543f3cb78d1b6762b270a6d23fbb30ca9f800d65f170e62b9cdc32ef1043557ab6ecaa1227478e3d1f7400d63f72f09171f68fb225f6951ca097dcb7e02b8b62e2b1b295bd25bbac7592460bb9fb2ad0a8b5d5f8c6af4bb5")
	finishedMessage := quic.StrtoByte("14000020fa61ec0293c98834f638c818866a8582cb6e1683204bafe1e8f0b22ca2d49b0c")

	clientkey := quic.StrtoByte("0000000000000000000000000000000000000000000000000000000000000000")
	serverkey := quic.StrtoByte("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")

	commonkey, _ := curve25519.X25519(clientkey, serverkey)

	chello = append(chello, serverHello...)
	tlsinfo.KeyBlockTLS13 = quic.KeyscheduleToMasterSecret(commonkey, chello)

	chello = append(chello, encryptedExtensions...)
	chello = append(chello, serverCertificate...)
	chello = append(chello, certificateVerify...)
	chello = append(chello, finishedMessage...)
	tlsinfo.HandshakeMessages = chello
	fmt.Printf("tls packet is %x\n", tlsinfo.HandshakeMessages)
	tlsinfo = quic.KeyscheduleToAppTraffic(tlsinfo)

	rawshort := quic.StrtoByte("5b1c83105391af6659528a0608870a0f71b8db45bf73fe653d0fa02f2cb1191f74891ad12255b75291c42f765b6c561c92af6f951ba68eaa0f7e5d74b5178636b1474c15a77bc254bb5123e06522f80a5ba611ab871bdaa6dc228d")
	parsed := quic.ParseRawQuicPacket(rawshort, true)
	shortpacket := parsed[0].Packet.(quic.ShortHeader)
	startPnumOffset := len(shortpacket.ToHeaderByte(shortpacket)) - 2

	unpPacket := quic.UnprotectHeader(startPnumOffset, parsed[0].RawPacket, tlsinfo.KeyBlockTLS13.ServerAppHPKey, false)
	unpshort := unpPacket[0].Packet.(quic.ShortHeader)

	keyblock := quic.QuicKeyBlock{
		ServerKey: tlsinfo.KeyBlockTLS13.ServerAppKey,
		ServerIV:  tlsinfo.KeyBlockTLS13.ServerAppIV,
	}

	plain := quic.DecryptQuicPayload(unpshort.PacketNumber, unpshort.ToHeaderByte(unpshort), unpshort.Payload, keyblock)
	newconn := quic.ParseQuicFrame(plain, 0)
	fmt.Printf("new connection id is %+v\n", newconn)

	tlsinfo.QPacketInfo.InitialPacketNumber++

	//var init quic.InitialPacket
	//ack := init.CreateInitialAckPacket(quicinfo)
	//fmt.Printf("ack packet is %x\n", ack)

	fin := quic.CreateClientFinished(tlsinfo.HandshakeMessages, tlsinfo.KeyBlockTLS13.ClientFinishedKey)
	fmt.Printf("finished crypto frame is %x\n", quic.ToPacket(fin))

}

func _() {

	var tlsinfo quic.TLSInfo
	var init quic.InitialPacket
	var initPacket, retryInit []byte
	tlsinfo.QPacketInfo = quic.QPacketInfo{
		DestinationConnID:   quic.StrtoByte("7b268ba2b1ced2e48ed34a0a38"),
		SourceConnID:        nil,
		Token:               nil,
		InitialPacketNumber: 0,
		PacketNumberLength:  2,
		CryptoFrameOffset:   0,
	}
	tlsinfo, initPacket = init.CreateInitialPacket(tlsinfo)
	fmt.Printf("initPacket is %x\n", initPacket)
	// 1増やす
	tlsinfo.QPacketInfo.InitialPacketNumber++

	recv := quic.ParseRawQuicPacket(quic.StrtoByte("f00000000100045306bcce4d980d67e740d1b668e76b52ca23f64addcda437e05054d512724a31b2f385a03e2dd0eff876df88c5c60c5d3d7315d9128b1c9df3e09494efb8956e6417966fd20d76d6a1e5589e423d4a91aed08131d1759881ef26ce26c84fe417b8e7e5d4becff564572c6feae8351b"), true)
	retryPacket := recv[0].Packet.(quic.RetryPacket)

	// ServerからのRetryパケットのSource Connection IDをDestination Connection IDとしてInitial Packetを生成する
	tlsinfo.QPacketInfo.DestinationConnID = retryPacket.LongHeader.SourceConnID
	tlsinfo.QPacketInfo.Token = retryPacket.RetryToken
	tlsinfo, retryInit = init.CreateInitialPacket(tlsinfo)

	fmt.Printf("retryInit is %x\n", retryInit)

	// ここでInitial PacketでServerHelloが、Handshake PacketでCertificateの途中まで返ってくる
	// recvhandshake[0]にInitial Packet(Server hello), [1]にHandshake Packet(Certificate~)
	recvPacket := quic.ParseRawQuicPacket(quic.StrtoByte("c70000000100044a4b30eb0040754e968ed438dd5ba1b6cafef2cb9c84ee9bc9efc838f64b7e4ac53396ff7aaa3fdc1fa2b94326d8141d41ffd5787f21f5f54e7a1c9ad9501d108463a6e272c7f1263aa23560a00a5ad5d41c0c79239f18a138a0bb8270e0d9dbd369f6ce1ce5f01d6176726a9046b539457f72df7081f0b27c01e275ef0000000100044a4b30eb44544cd3b74f603556b6c49d4a126b108397a9b59e8d3b7f1843bf9fb1a09ed68f2d858bb5c16149c6f37a938c589a9ed8ae9c4342de373fc48c97a3d37c9db6d7b59b7610e34628062b8c97efa6675e43e266650589d360b45cd05878c30955b7e08ac0b7b90e6eb2c356d8806ab1389748b710141b008f43969e31f72485257ab7c938d95f08d0315e3d8529855b5ffb32795f9c39da4180e54748669fe7939b2f17a1f3e53d8bb025ac4a99e4afda8ad45ea41eff53b2f73358e561545af1622412a29b71d51e3643a09579d417900f779861d1581b5aaddfa0b062bb8b1087121608f5ff055fe84c37a8d3f1648dcb96f01cb021a91d88e28283cbddc649658692f1598bf78146bdcfd2e20e61801b5616cac088f594cb92b0a5b1d567cf97f1bd7cfdeead4e2ca4da15a1bcf50bc032393a656cc5a1556be9bde6f00770c8329a530eef3a4c8327fde355a09c88759c889b40bc32c8301b911b2401478ea2b6ec05008c71b4b7a88f423b5672286c092dcc6dd66a530e46a99cd426567616aa9f5c7e96d0bdf638730c6e04d71836ea7820cbc1b52ff923238a0df00533b819b89f5f89b22c44f178cdaf6840908f5eb3cbe03778b6038f4ca689e9501174dc7cbe9db91afe08c604d931c20bcbde95e90225b49a4d95cc7ce60762e35ba9af851eac9cc17a181baaeea374c0ca9875f9b08880d84c0f2ae1cc98dc588eb282448777bda611b53e8ef6ca8350ea0a4dd7bf05ae1d31bb98b7c85660104b15a2970e9df891a0a89ba6846ec091a95d82a9e88defc5538bca59f47e1be59cbfd7bdeb03bca81bdc1b80f5104c66a7c1b6290e5893938e3f9345b8637a0d22e68d1527dff1af299e9d3faa40878dc1c9b829a7d367aa89250f6c9ca30f8fb3af171cb6a6ce1192df091ec31c5c778d28394a9e5821a64218b254129969a3baecd9a430e243aa20af50194bec23aecd5edcf3c9e719a6d7dd5a3b3fedb7ad5cbe40bce0d0d1457ae06242a282e39a41a19963f9140323c35458c3278a3d90c373a6ae95cb94a81ce2ce6295dee518390a856ba1bade91e8c0ce585509cce067eabb83863a70e534aa69dcebdfbdb3e6e50f1558df5a9992355598f19f66612cc6622c91e5f6e3e260fd06bfd4f0b96a0f700ee3d39c1610673d87df7d2efceb06d1e1128d98265f0055978485db145f320e8ecda45979a4c7553f6cfa84da7ddf1cf9c00a975ab747844dc25d5061a4fb7d317195ce76ffedb9a8e62d1401a12682796f622b72f17800bea5499aa628f6d0062ca8f82224732e79b72be159d150b9fdc05c56cd007a92ad21c524dc333436e9fb89a333524a76c9cf09dab065161e8c93e8a1e6830b4e1800562bfb93dcd0ae52f433be365f8bcc2ab3101ac37b0e618f532fee4a2edbf6013d2de13b0600fc246e1de872fdad123816dd8d8a0735d9a444c7d6a4699919eac9f0b21356e860e34078c781375cf1304a9337e21301186e5a73165c2a2df71749a817ee05618230d2742fe578e421a2369111c06c6a74f866302b40b9d1dd93dfe990a382f5b73c91f7"), true)

	// Initial packet を処理する
	recvInitPacket := recvPacket[0].Packet.(quic.InitialPacket)
	// [0]にACK, [1]にCRYPTO(ServerHello)が入る
	qframes := recvInitPacket.ToPlainQuicPacket(recvInitPacket, recvPacket[0].RawPacket, tlsinfo)

	var shello quic.ServerHello
	tlsPackets, isfrag := quic.ParseTLSHandshake(qframes[1].(quic.CryptoFrame).Data)
	if !isfrag {
		shello = tlsPackets[0].(quic.ServerHello)
	}
	commonkey := quic.GenerateCommonKey(shello.TLSExtensions, tlsinfo.ECDHEKeys.PrivateKey)
	// server hello を追加
	tlsinfo.HandshakeMessages = append(tlsinfo.HandshakeMessages, qframes[1].(quic.CryptoFrame).Data...)
	// 鍵導出を実行
	tlsinfo.KeyBlockTLS13 = quic.KeyscheduleToMasterSecret(commonkey, tlsinfo.HandshakeMessages)

	// Handshake Packetを処理
	handshake := recvPacket[1].Packet.(quic.HandshakePacket)
	frames := handshake.ToPlainQuicPacket(handshake, recvPacket[1].RawPacket, tlsinfo)

	tlsPackets, frag := quic.ParseTLSHandshake(frames[0].(quic.CryptoFrame).Data)

	var fragPacket []quic.ParsedQuicPacket
	// パケットが途中で途切れてるなら次のパケットを読み込む
	if frag {
		fmt.Println("is frag true")
		// [0]にTLSパケットの続き(Certificate, CertificateVerify, Finished)
		// [1]にShort HeaderのNew Connection ID Frameが3つ
		fragPacket = quic.ParseRawQuicPacket(quic.StrtoByte("ea0000000100044a4b30eb41c1184320f0b3f1c5af2bd489437dc37139b30c1c810134c8a5c82b6723a5d0f7482827a6bfb4d254f5d88fb12afc218b9004f62be63ac36f9dc93f10b4c1e85c0e563037d577975400db6d74db34f60668546ded459c501bf3194207ce227249dcbe31fa844cd397db5af58d63136d0ab9316279f833d8a2183beaa09469e6123383eb39c9f96be6c996704858bbc21b2e20ea7faca53cdfe6db656bb1bd7e37a11f05be31058dd5a0d4c980235ce4c8cc348ddad5beda4b8872368cf40acba55239195f9658ed950ed1b8bbe712313029a189b998b7c48c2d5e93a6759d9d6b3e7e9de6b5cc051b90c350b9675e084d584651c7f2d969aea292b770daa4a4e4ea34b70b0b57a5da0088d4f465087803ad5a94ac79c5e30a63156e77e7f93851591fc262e3c5439f379a56bb34e012ac3fc94c86177d9311e1a98a1fffd896de7bdfec06acf135f72d30896b07f9d4bc4e6b6ae9ebeee52aaa178e65f8d14f6003d0226a395ec6b6f8c69de5c0d3a61fccfbb0523c40504dd8058bdb125a6f317f802dc3fd0d1e7a5dececa9d1016db873ab2cc32ba218cca61210bd8977c512c91f676dcd07dc06a2a94376ffabc6774d9240d2f1e06f6ec8f551490318ff03cf925b1c83105391af6659528a0608870a0f71b8db45bf73fe653d0fa02f2cb1191f74891ad12255b75291c42f765b6c561c92af6f951ba68eaa0f7e5d74b5178636b1474c15a77bc254bb5123e06522f80a5ba611ab871bdaa6dc228d"), true)
		tlsinfo.QPacketInfo.CryptoFrameOffset = quic.SumLengthByte(frames[0].(quic.CryptoFrame).Length)
	}
	//
	fraghs := fragPacket[0].Packet.(quic.HandshakePacket)
	fragedhsframe := fraghs.ToPlainQuicPacket(fraghs, fragPacket[0].RawPacket, tlsinfo)

	// 1つ前のCrypto Frameの途中までのデータに続きのデータをくっつける
	// Encrypted Extnsions, Server Certificate, Certificate Verify, Finishedの完全なパケットが生成
	tlsCertificate := frames[0].(quic.CryptoFrame).Data
	tlsCertificate = append(tlsCertificate, fragedhsframe[0].(quic.CryptoFrame).Data...)

	tlspacket, frag := quic.ParseTLSHandshake(tlsCertificate)
	if !frag {
		_ = tlspacket
	}

	// ClientHello, ServerHello, EncryptedExtension, ServerCertificate, CertificateVerify, Fnished
	tlsinfo.HandshakeMessages = append(tlsinfo.HandshakeMessages, tlsCertificate...)
	// Application用の鍵導出を行う
	tlsinfo = quic.KeyscheduleToAppTraffic(tlsinfo)

	unpshort := fragPacket[1].Packet.(quic.ShortHeader)
	frames = unpshort.ToPlainQuicPacket(unpshort, fragPacket[1].RawPacket, tlsinfo)

	fmt.Printf("new_connection_id is %+v\n", frames[0])

	tlsinfo.QPacketInfo.InitialPacketNumber++
	ack := init.CreateInitialAckPacket(tlsinfo)
	fmt.Printf("ACK packet is %x\n", ack)

}

//
//func _() {
//	dcid := quic.StrtoByte("7b268ba2b1ced2e48ed34a0a38")
//	keyblock := quic.CreateQuicInitialSecret(dcid)
//	quic.PrintPacket(keyblock.ClientIV, "ClientIV")
//	chello := quic.StrtoByte("060041340100013003030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000e10000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100014001211717569632d6563686f2d6578616d706c6500120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b740039003e420b041fad788e0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00200100")
//
//	initPacket := quic.NewInitialPacket(dcid, nil, nil, 0, 2)
//	paddingLength := 1252 - len(quic.ToPacket(initPacket.LongHeader)) -
//		len(initPacket.PacketNumber) - len(chello) - 16 - 4
//
//	fmt.Printf("padding length is %d\n", paddingLength)
//	// set Crypto Frame(client hello)
//	initPacket.Payload = quic.UnshiftPaddingFrame(chello, paddingLength)
//	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
//	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
//	// 可変長整数のエンコードをしてLengthをセット
//	initPacket.Length = quic.EncodeVariableInt(length)
//
//	headerByte := quic.ToPacket(initPacket.LongHeader)
//	// set Token Length
//	headerByte = append(headerByte, initPacket.TokenLength...)
//	//headerByte = append(headerByte, initPacket.Token...)
//	headerByte = append(headerByte, initPacket.Length...)
//	headerByte = append(headerByte, initPacket.PacketNumber...)
//	quic.PrintPacket(headerByte, "header")
//
//	enctext := quic.EncryptClientPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
//	//quic.PrintPacket(enctext, "enc payload")
//
//	packet := headerByte
//	packet = append(packet, enctext...)
//	protectPacket := quic.ProtectHeader(len(headerByte)-2, packet, keyblock.ClientHeaderProtection, true)
//	quic.PrintPacket(protectPacket, "protect packet")
//
//}

func _() {
	nonce := quic.StrtoByte("a1fc318258cb919bcfcc0adc")
	payload := quic.StrtoByte("b74f603556b6c49d4a126b108397a9b59e8d3b7f1843bf9fb1a09ed68f2d858bb5c16149c6f37a938c589a9ed8ae9c4342de373fc48c97a3d37c9db6d7b59b7610e34628062b8c97efa6675e43e266650589d360b45cd05878c30955b7e08ac0b7b90e6eb2c356d8806ab1389748b710141b008f43969e31f72485257ab7c938d95f08d0315e3d8529855b5ffb32795f9c39da4180e54748669fe7939b2f17a1f3e53d8bb025ac4a99e4afda8ad45ea41eff53b2f73358e561545af1622412a29b71d51e3643a09579d417900f779861d1581b5aaddfa0b062bb8b1087121608f5ff055fe84c37a8d3f1648dcb96f01cb021a91d88e28283cbddc649658692f1598bf78146bdcfd2e20e61801b5616cac088f594cb92b0a5b1d567cf97f1bd7cfdeead4e2ca4da15a1bcf50bc032393a656cc5a1556be9bde6f00770c8329a530eef3a4c8327fde355a09c88759c889b40bc32c8301b911b2401478ea2b6ec05008c71b4b7a88f423b5672286c092dcc6dd66a530e46a99cd426567616aa9f5c7e96d0bdf638730c6e04d71836ea7820cbc1b52ff923238a0df00533b819b89f5f89b22c44f178cdaf6840908f5eb3cbe03778b6038f4ca689e9501174dc7cbe9db91afe08c604d931c20bcbde95e90225b49a4d95cc7ce60762e35ba9af851eac9cc17a181baaeea374c0ca9875f9b08880d84c0f2ae1cc98dc588eb282448777bda611b53e8ef6ca8350ea0a4dd7bf05ae1d31bb98b7c85660104b15a2970e9df891a0a89ba6846ec091a95d82a9e88defc5538bca59f47e1be59cbfd7bdeb03bca81bdc1b80f5104c66a7c1b6290e5893938e3f9345b8637a0d22e68d1527dff1af299e9d3faa40878dc1c9b829a7d367aa89250f6c9ca30f8fb3af171cb6a6ce1192df091ec31c5c778d28394a9e5821a64218b254129969a3baecd9a430e243aa20af50194bec23aecd5edcf3c9e719a6d7dd5a3b3fedb7ad5cbe40bce0d0d1457ae06242a282e39a41a19963f9140323c35458c3278a3d90c373a6ae95cb94a81ce2ce6295dee518390a856ba1bade91e8c0ce585509cce067eabb83863a70e534aa69dcebdfbdb3e6e50f1558df5a9992355598f19f66612cc6622c91e5f6e3e260fd06bfd4f0b96a0f700ee3d39c1610673d87df7d2efceb06d1e1128d98265f0055978485db145f320e8ecda45979a4c7553f6cfa84da7ddf1cf9c00a975ab747844dc25d5061a4fb7d317195ce76ffedb9a8e62d1401a12682796f622b72f17800bea5499aa628f6d0062ca8f82224732e79b72be159d150b9fdc05c56cd007a92ad21c524dc333436e9fb89a333524a76c9cf09dab065161e8c93e8a1e6830b4e1800562bfb93dcd0ae52f433be365f8bcc2ab3101ac37b0e618f532fee4a2edbf6013d2de13b0600fc246e1de872fdad123816dd8d8a0735d9a444c7d6a4699919eac9f0b21356e860e34078c781375cf1304a9337e21301186e5a73165c2a2df71749a817ee05618230d2742fe578e421a2369111c06c6a74f866302b40b9d1dd93dfe990a382f5b73c91f7")
	header := quic.StrtoByte("e10000000100044a4b30eb44540000")
	// AES-128-GCMで暗号化する
	block, _ := aes.NewCipher(quic.StrtoByte("564dce577597084aa28d42386e0a0586"))
	aesgcm, _ := cipher.NewGCM(block)
	fmt.Printf("nonce is %x, header is %x\n", nonce, header)
	encryptedMessage, err := aesgcm.Open(nil, nonce, payload, header)
	if err != nil {
		log.Fatal(err)
	}
	quic.PrintPacket(encryptedMessage, "plain text")
}

func _() {
	fmt.Println("--- decryptHandshake ---")
	destconnID := quic.StrtoByte("5306bcce")
	// destination connection id からキーを生成する
	keyblock := quic.CreateQuicInitialSecret(destconnID)
	_ = keyblock

	//client hello
	handshakeMessages := quic.StrtoByte("0100013003030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000e10000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100014001211717569632d6563686f2d6578616d706c6500120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b740039003e420b041fad788e0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00200100")
	//server hello
	handshakeMessages = append(handshakeMessages, quic.StrtoByte("020000560303000000000000000000000000000000000000000000000000000000000000000000130100002e002b0002030400330024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")...)

	privateKey := quic.StrtoByte("0000000000000000000000000000000000000000000000000000000000000000")
	serverPubkey := quic.StrtoByte("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")
	commonKey, _ := curve25519.X25519(privateKey, serverPubkey)

	tls13Keyblock := quic.KeyscheduleToMasterSecret(commonKey, handshakeMessages)

	rawHandshakePacket := quic.StrtoByte("ef0000000100044a4b30eb44544cd3b74f603556b6c49d4a126b108397a9b59e8d3b7f1843bf9fb1a09ed68f2d858bb5c16149c6f37a938c589a9ed8ae9c4342de373fc48c97a3d37c9db6d7b59b7610e34628062b8c97efa6675e43e266650589d360b45cd05878c30955b7e08ac0b7b90e6eb2c356d8806ab1389748b710141b008f43969e31f72485257ab7c938d95f08d0315e3d8529855b5ffb32795f9c39da4180e54748669fe7939b2f17a1f3e53d8bb025ac4a99e4afda8ad45ea41eff53b2f73358e561545af1622412a29b71d51e3643a09579d417900f779861d1581b5aaddfa0b062bb8b1087121608f5ff055fe84c37a8d3f1648dcb96f01cb021a91d88e28283cbddc649658692f1598bf78146bdcfd2e20e61801b5616cac088f594cb92b0a5b1d567cf97f1bd7cfdeead4e2ca4da15a1bcf50bc032393a656cc5a1556be9bde6f00770c8329a530eef3a4c8327fde355a09c88759c889b40bc32c8301b911b2401478ea2b6ec05008c71b4b7a88f423b5672286c092dcc6dd66a530e46a99cd426567616aa9f5c7e96d0bdf638730c6e04d71836ea7820cbc1b52ff923238a0df00533b819b89f5f89b22c44f178cdaf6840908f5eb3cbe03778b6038f4ca689e9501174dc7cbe9db91afe08c604d931c20bcbde95e90225b49a4d95cc7ce60762e35ba9af851eac9cc17a181baaeea374c0ca9875f9b08880d84c0f2ae1cc98dc588eb282448777bda611b53e8ef6ca8350ea0a4dd7bf05ae1d31bb98b7c85660104b15a2970e9df891a0a89ba6846ec091a95d82a9e88defc5538bca59f47e1be59cbfd7bdeb03bca81bdc1b80f5104c66a7c1b6290e5893938e3f9345b8637a0d22e68d1527dff1af299e9d3faa40878dc1c9b829a7d367aa89250f6c9ca30f8fb3af171cb6a6ce1192df091ec31c5c778d28394a9e5821a64218b254129969a3baecd9a430e243aa20af50194bec23aecd5edcf3c9e719a6d7dd5a3b3fedb7ad5cbe40bce0d0d1457ae06242a282e39a41a19963f9140323c35458c3278a3d90c373a6ae95cb94a81ce2ce6295dee518390a856ba1bade91e8c0ce585509cce067eabb83863a70e534aa69dcebdfbdb3e6e50f1558df5a9992355598f19f66612cc6622c91e5f6e3e260fd06bfd4f0b96a0f700ee3d39c1610673d87df7d2efceb06d1e1128d98265f0055978485db145f320e8ecda45979a4c7553f6cfa84da7ddf1cf9c00a975ab747844dc25d5061a4fb7d317195ce76ffedb9a8e62d1401a12682796f622b72f17800bea5499aa628f6d0062ca8f82224732e79b72be159d150b9fdc05c56cd007a92ad21c524dc333436e9fb89a333524a76c9cf09dab065161e8c93e8a1e6830b4e1800562bfb93dcd0ae52f433be365f8bcc2ab3101ac37b0e618f532fee4a2edbf6013d2de13b0600fc246e1de872fdad123816dd8d8a0735d9a444c7d6a4699919eac9f0b21356e860e34078c781375cf1304a9337e21301186e5a73165c2a2df71749a817ee05618230d2742fe578e421a2369111c06c6a74f866302b40b9d1dd93dfe990a382f5b73c91f7")
	//rawHandshakePacket := quic.StrtoByte("cb000000010004a37891c200407530cc4a7dac5a2870abcef4d599d9ae9fb35835b0b75d16c3eea68730928a3c78567f3bb0f448cc3ee26d554400a1d63686225c41e7b4041ddaf00486de22c863323407a55b1840d24415cad5ad2fd773e1de8e1b4035083cf0b0301b9f0d04b295d06ac6149d5c24eed9b8290c465f6906bde962f1")
	parsed := quic.ParseRawQuicPacket(rawHandshakePacket, true)

	rawHandshake := parsed[0].Packet.(quic.HandshakePacket)
	// 2 = パケット番号の長さ
	startPnumOffset := len(rawHandshakePacket) - len(rawHandshake.Payload) - 2

	unprotect := quic.UnprotectHeader(startPnumOffset, rawHandshakePacket, tls13Keyblock.ServerHandshakeHPKey, true)
	handshake := unprotect[0].Packet.(quic.HandshakePacket)
	headerByte := quic.ToPacket(handshake.LongHeader)
	headerByte = append(headerByte, quic.EncodeVariableInt(int((quic.SumLengthByte(handshake.Length))))...)
	headerByte = append(headerByte, handshake.PacketNumber...)

	quic.PrintPacket(headerByte, "unprotect header packet")

	serverkey := quic.QuicKeyBlock{
		ServerKey: tls13Keyblock.ServerHandshakeKey,
		ServerIV:  tls13Keyblock.ServerHandshakeIV,
		//ServerKey: quic.StrtoByte("564dce577597084aa28d42386e0a0586"),
		//ServerIV:  quic.StrtoByte("a1fc318258cb919bcfcc0adc"),
	}
	fmt.Printf("server key is %x\n", serverkey.ServerKey)
	plain := quic.DecryptQuicPayload(handshake.PacketNumber, headerByte, handshake.Payload, serverkey)
	fmt.Printf("plain  is %x\n", plain)

	frames := quic.ParseQuicFrame(plain, 0)[0].(quic.CryptoFrame)

	fmt.Printf("frames : %x\n", frames.Data)

}
