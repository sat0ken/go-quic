package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"quic"
)

var localAddr = []byte{127, 0, 0, 1}

const port = 10443

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
	//Retryに対してInitial Packetを送り返すときには受信したSourceConnIDをDestinationConnectionIDにセットする
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
	//
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
	//fmt.Printf("recv rawnci packet is %+v\n", rawnci[0])

	//var short quic.ShortHeader
	shortByte := short.CreateShortHeaderPacket(tlsinfo, quic.NewControlStream())
	tlsinfo.QPacketInfo.ShortHeaderPacketNumber++

	//
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
	fmt.Printf("frame %+v\n", stream)

	h3data := quic.ParseHTTP3(stream.StreamData)
	fmt.Printf("message from http3 server is %s\n", h3data[1].Payload)
}

//func handshakePacket() {
//	destconnID := quic.StrtoByte("5306bcce")
//	// destination connection id からキーを生成する
//	keyblock := quic.CreateQuicInitialSecret(destconnID)
//
//	// local-quic-go.pacpng No.4のパケット
//	h := quic.StrtoByte("c70000000100044a4b30eb0040754e968ed438dd5ba1b6cafef2cb9c84ee9bc9efc838f64b7e4ac53396ff7aaa3fdc1fa2b94326d8141d41ffd5787f21f5f54e7a1c9ad9501d108463a6e272c7f1263aa23560a00a5ad5d41c0c79239f18a138a0bb8270e0d9dbd369f6ce1ce5f01d6176726a9046b539457f72df7081f0b27c01e275ef0000000100044a4b30eb44544cd3b74f603556b6c49d4a126b108397a9b59e8d3b7f1843bf9fb1a09ed68f2d858bb5c16149c6f37a938c589a9ed8ae9c4342de373fc48c97a3d37c9db6d7b59b7610e34628062b8c97efa6675e43e266650589d360b45cd05878c30955b7e08ac0b7b90e6eb2c356d8806ab1389748b710141b008f43969e31f72485257ab7c938d95f08d0315e3d8529855b5ffb32795f9c39da4180e54748669fe7939b2f17a1f3e53d8bb025ac4a99e4afda8ad45ea41eff53b2f73358e561545af1622412a29b71d51e3643a09579d417900f779861d1581b5aaddfa0b062bb8b1087121608f5ff055fe84c37a8d3f1648dcb96f01cb021a91d88e28283cbddc649658692f1598bf78146bdcfd2e20e61801b5616cac088f594cb92b0a5b1d567cf97f1bd7cfdeead4e2ca4da15a1bcf50bc032393a656cc5a1556be9bde6f00770c8329a530eef3a4c8327fde355a09c88759c889b40bc32c8301b911b2401478ea2b6ec05008c71b4b7a88f423b5672286c092dcc6dd66a530e46a99cd426567616aa9f5c7e96d0bdf638730c6e04d71836ea7820cbc1b52ff923238a0df00533b819b89f5f89b22c44f178cdaf6840908f5eb3cbe03778b6038f4ca689e9501174dc7cbe9db91afe08c604d931c20bcbde95e90225b49a4d95cc7ce60762e35ba9af851eac9cc17a181baaeea374c0ca9875f9b08880d84c0f2ae1cc98dc588eb282448777bda611b53e8ef6ca8350ea0a4dd7bf05ae1d31bb98b7c85660104b15a2970e9df891a0a89ba6846ec091a95d82a9e88defc5538bca59f47e1be59cbfd7bdeb03bca81bdc1b80f5104c66a7c1b6290e5893938e3f9345b8637a0d22e68d1527dff1af299e9d3faa40878dc1c9b829a7d367aa89250f6c9ca30f8fb3af171cb6a6ce1192df091ec31c5c778d28394a9e5821a64218b254129969a3baecd9a430e243aa20af50194bec23aecd5edcf3c9e719a6d7dd5a3b3fedb7ad5cbe40bce0d0d1457ae06242a282e39a41a19963f9140323c35458c3278a3d90c373a6ae95cb94a81ce2ce6295dee518390a856ba1bade91e8c0ce585509cce067eabb83863a70e534aa69dcebdfbdb3e6e50f1558df5a9992355598f19f66612cc6622c91e5f6e3e260fd06bfd4f0b96a0f700ee3d39c1610673d87df7d2efceb06d1e1128d98265f0055978485db145f320e8ecda45979a4c7553f6cfa84da7ddf1cf9c00a975ab747844dc25d5061a4fb7d317195ce76ffedb9a8e62d1401a12682796f622b72f17800bea5499aa628f6d0062ca8f82224732e79b72be159d150b9fdc05c56cd007a92ad21c524dc333436e9fb89a333524a76c9cf09dab065161e8c93e8a1e6830b4e1800562bfb93dcd0ae52f433be365f8bcc2ab3101ac37b0e618f532fee4a2edbf6013d2de13b0600fc246e1de872fdad123816dd8d8a0735d9a444c7d6a4699919eac9f0b21356e860e34078c781375cf1304a9337e21301186e5a73165c2a2df71749a817ee05618230d2742fe578e421a2369111c06c6a74f866302b40b9d1dd93dfe990a382f5b73c91f7")
//	// parsed[0]にInitial Packet(Server hello), [1]にHandshake Packet(Certificate~)
//	parsed := quic.ParseRawQuicPacket(h, true)
//	initPacket := parsed[0].Packet.(quic.InitialPacket)
//	startPnumOffset := len(initPacket.ToHeaderByte(initPacket, false)) - 2
//
//	unpInit := quic.UnprotectHeader(startPnumOffset, parsed[0].RawPacket, keyblock.ServerHeaderProtection, true)
//	init := unpInit[0].Packet.(quic.InitialPacket)
//
//	// Initial Packetを復号
//	plain := quic.DecryptQuicPayload(init.PacketNumber, init.ToHeaderByte(init, true), init.Payload, keyblock)
//	qframes := quic.ParseQuicFrame(plain, 0)
//
//	fmt.Printf("plain is %x\n", plain)
//
//	var shello quic.ServerHello
//	tlsPackets, isfrag := quic.ParseTLSHandshake(qframes[1].(quic.CryptoFrame).Data)
//	if !isfrag {
//		shello = tlsPackets[0].(quic.ServerHello)
//	}
//
//	fmt.Printf("server hello is %x\n", qframes[1].(quic.CryptoFrame).Data)
//
//	privateKey := quic.StrtoByte("0000000000000000000000000000000000000000000000000000000000000000")
//	commonkey := quic.GenerateCommonKey(shello.TLSExtensions, privateKey)
//
//	chello := quic.StrtoByte("0100013003030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000e10000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100014001211717569632d6563686f2d6578616d706c6500120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b740039003e420b041fad788e0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00200100")
//
//	// server hello を追加
//	chello = append(chello, qframes[1].(quic.CryptoFrame).Data...)
//	// 鍵導出を実行
//	tls13Keyblock := quic.KeyscheduleToMasterSecret(commonkey, chello)
//
//	handshake := parsed[1].Packet.(quic.HandshakePacket)
//	startPnumOffset = len(handshake.ToHeaderByte(handshake, false)) - 2
//
//	unpPacket := quic.UnprotectHeader(startPnumOffset, parsed[1].RawPacket, tls13Keyblock.ServerHandshakeHPKey, true)
//	unpHandshake := unpPacket[0].Packet.(quic.HandshakePacket)
//	serverkey := quic.QuicKeyBlock{
//		ServerKey: tls13Keyblock.ServerHandshakeKey,
//		ServerIV:  tls13Keyblock.ServerHandshakeIV,
//	}
//
//	plain = quic.DecryptQuicPayload(unpHandshake.PacketNumber, unpHandshake.ToHeaderByte(unpHandshake, true), unpHandshake.Payload, serverkey)
//	frames := quic.ParseQuicFrame(plain, 0)
//
//	tlsPackets, frag := quic.ParseTLSHandshake(frames[0].(quic.CryptoFrame).Data)
//	fmt.Printf("isfrag %v\n", frag)
//
//	// frag が true なら recvをもう1回呼んで次のパケットを読み込む
//	// local-quic-go.pacpng No.5のパケット
//	recvfrag := quic.StrtoByte("ea0000000100044a4b30eb41c1184320f0b3f1c5af2bd489437dc37139b30c1c810134c8a5c82b6723a5d0f7482827a6bfb4d254f5d88fb12afc218b9004f62be63ac36f9dc93f10b4c1e85c0e563037d577975400db6d74db34f60668546ded459c501bf3194207ce227249dcbe31fa844cd397db5af58d63136d0ab9316279f833d8a2183beaa09469e6123383eb39c9f96be6c996704858bbc21b2e20ea7faca53cdfe6db656bb1bd7e37a11f05be31058dd5a0d4c980235ce4c8cc348ddad5beda4b8872368cf40acba55239195f9658ed950ed1b8bbe712313029a189b998b7c48c2d5e93a6759d9d6b3e7e9de6b5cc051b90c350b9675e084d584651c7f2d969aea292b770daa4a4e4ea34b70b0b57a5da0088d4f465087803ad5a94ac79c5e30a63156e77e7f93851591fc262e3c5439f379a56bb34e012ac3fc94c86177d9311e1a98a1fffd896de7bdfec06acf135f72d30896b07f9d4bc4e6b6ae9ebeee52aaa178e65f8d14f6003d0226a395ec6b6f8c69de5c0d3a61fccfbb0523c40504dd8058bdb125a6f317f802dc3fd0d1e7a5dececa9d1016db873ab2cc32ba218cca61210bd8977c512c91f676dcd07dc06a2a94376ffabc6774d9240d2f1e06f6ec8f551490318ff03cf925b1c83105391af6659528a0608870a0f71b8db45bf73fe653d0fa02f2cb1191f74891ad12255b75291c42f765b6c561c92af6f951ba68eaa0f7e5d74b5178636b1474c15a77bc254bb5123e06522f80a5ba611ab871bdaa6dc228d")
//	parsed = quic.ParseRawQuicPacket(recvfrag, true)
//	fragedhs := parsed[0].Packet.(quic.HandshakePacket)
//
//	startPnumOffset = len(fragedhs.ToHeaderByte(fragedhs, false)) - 2
//	unpParsed := quic.UnprotectHeader(startPnumOffset, parsed[0].RawPacket, tls13Keyblock.ServerHandshakeHPKey, true)
//	unpFraghs := unpParsed[0].Packet.(quic.HandshakePacket)
//
//	fragplain := quic.DecryptQuicPayload(unpFraghs.PacketNumber, unpFraghs.ToHeaderByte(unpFraghs, true), unpFraghs.Payload, serverkey)
//
//	fmt.Printf("frag plain is %x\n", fragplain)
//	frames = quic.ParseQuicFrame(fragplain, 0)
//	fmt.Printf("%x\n", frames[0].(quic.CryptoFrame).Data)
//
//	// TLS1.3の鍵導出をする
//
//	//short := parsed[1].Packet.(quic.QuicShortHeaderPacket)
//	//startPnumOffset = len(short.ToHeaderByte(short)) - 2
//	//unpParsed = quic.UnprotectHeader(startPnumOffset, parsed[1].RawPacket, tls13Keyblock.ServerHandshakeHPKey)
//	//unpshort := unpParsed[0].Packet.(quic.QuicShortHeaderPacket)
//	//
//	//fmt.Printf("short header byte is %x\n", unpshort.ToHeaderByte(unpshort))
//
//}

func _() {

	c1 := quic.StrtoByte("0600443e08000090008e00100014001211717569632d6563686f2d6578616d706c650039007241ae0dff4c11f1b2cd93f99dc5cea1cc0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c0002101ae14003acb9d4c32fb8ab4ea68e7693000d7b268ba2b1ced2e48ed34a0a380e01040f044a4b30eb10045306bcce2001000b0004240000042000041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262d")
	parsed := quic.ParseQuicFrame(c1, 0)
	tlsPacket, frag := quic.ParseTLSHandshake(parsed[0].(quic.CryptoFrame).Data)
	fmt.Printf("frag is %v\n", frag)

	c2 := quic.StrtoByte("06443e41aaa4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee00000f00010408040100b9e4e4195c38fa814824567a0a3a5dbf667c93eb0ac0825d329d2bed57fa473817c47e811b3e803ba8020582ec67fe30d47f06b464e89684f064a0829272162cee7e2e2c692ffbade10bf8708ab6faf6bf5315ae2b200b9aac82d99e7e0dd473ee4ba2593490c4c27bc9caa9033e4e856018ab070d13d7eaca63c2b7a91a2f7d7ab2fef50d4d26fbc53d690c1fbc8ce8131215ccffba292cfcb4072f2a148ec036f0f72a32e16088543f3cb78d1b6762b270a6d23fbb30ca9f800d65f170e62b9cdc32ef1043557ab6ecaa1227478e3d1f7400d63f72f09171f68fb225f6951ca097dcb7e02b8b62e2b1b295bd25bbac7592460bb9fb2ad0a8b5d5f8c6af4bb514000020fa61ec0293c98834f638c818866a8582cb6e1683204bafe1e8f0b22ca2d49b0c")

	// packetがfragmentだった場合、Crypto FrameのOffsetが1つ前のCrypto FrameのLengthになる。というのもPayloadは前のCrypto Frameの続きであるから
	if frag {
		offset := quic.SumLengthByte(parsed[0].(quic.CryptoFrame).Length)
		fmt.Printf("Next Crypto Frame offset is %x\n", quic.EncodeVariableInt(int(offset)))
		fragparsed := quic.ParseQuicFrame(c2, offset)

		fmt.Printf("%+v\n", fragparsed)
		tlspacket := tlsPacket[1].(quic.FragmentTLSPacket).Packet
		tlspacket = append(tlspacket, fragparsed[0].(quic.CryptoFrame).Data...)

		tls, frag := quic.ParseTLSHandshake(tlspacket)
		fmt.Printf("frag is %v, tls packet is %+v\n", frag, tls)

	}

	//sendinitpacket()
	//fraghandshake()
	//handshakePacket()
}

func _() {
	serverkey := quic.StrtoByte("ebc157ee3c04f773b2ba255513c143d1")

	block, _ := aes.NewCipher(serverkey)
	aesgcm, _ := cipher.NewGCM(block)

	packetnum := quic.StrtoByte("d4f0d561c75a4dcbe6d76c87")
	payload := quic.StrtoByte("d36165f8aca3c7ab36269e318ce627674b1a334f31eb465df52989bb4ab5a340c7344c9e5275a1474a75120ce96ef49543c2ba3ff94580e37cc47ad098bbe2698fa5e5504511c8a2e38e165391e76a93cee98244bc9b41a78d54f8f405fc796755091c82e316f1dcd3a47f6dd0b164d751f274ea530fd794f8c3c79f31b461e054c73e68b19f2eb2189a468ee32685a2e12cddd3be2a325d2d010b293e0a8549d9f1119f083d8d39610faef92003d53ebb3670a1d50e5cb0860227402f91f6fc5f9e7427474f9e6c702625c2d7deb54c9364631467244ea49d6fa4aa2a790abf8a060791064391a70808a320c9c061b1dcef41c097f8d817378fc7c63a2cc6477861ab2409ea0c7d4561c415b56ae4aacad1f7a52a33e277051465216e173cea4eaad253910b2c49a1ff0dc00a3fc5837fabd4db8e88bbec7ae6a02ca2e0fe5dd9e5bc5e549634ec6bcff13727e39a05a53672da4d3e0c3d12b9e281e822895df592c0e098f161526e01f3d90764c6c6dd3fc82bdb46f2cf9a1849d0717ae82dda562b236c566c456330e94e2bcc144361c337fbf13235361b8f3adf2c85901d851e1d6108cd354e1662665ac8e9b0d8ce012edd6c5720c9ed1fddc18d278d64252b7fac5992b54ad8bfefa70d5dbf43158cc62a509631f115b7a87f2be5d112092cde94f2fb9745c895b71cbf4b147515c41369e93d1c38ed9dd19609241fbaa63055ed639641d2aed812e065c6731ca86bbba5b971f1b194eaa04dd295cb6944d54f570aae341d0901543abcc4dd9a67e78e0f8adc61ca465ba87dad5cfaf2e210ff8f426e7d07b04133d14cf9f9a612943785f0a554a3c7f8b3e20cfd4e4572282bcf2b8b863992aa9987fa938fcd490f7130bd7121217ca461ec3cb3c77b722d8e9e8aa639dc1a03d6c226d41b2c309d185fa19a7fc8a31aab7e0cd1ed5d2a2a9d2b97e9ca457bbe91df83cde7a9b160de6c5bbcbfd480cf50774d81944096a81e6c6d396f05ef6a8b11eb4ec02eddd09d21fd920061e0236f9d6b0e43eabff53c8b844d913ce638da7cb606180c97f7be10c037c70bee0fc4e97113de2ccae64853b331ae99473ceaaa068378cfc5c17357233ac9b52e60ac837c9f9c502152ac005f8d294d0c797dde3ab34c1dff8e7a5e27f615c348483665282838ef191acbb8a411e544bdb7a63e0cab4372b8094cb82bf4827f7e89748062df139192df24b004cd74c590c493d0095a1c9be95e3d45c40ace07949ff5fa8ac7f8f0e0b65b92110601bcea56fa0fab6e470880e33f7ae5f7f4dff8d62091692093a3be2f6d99cd7330e8fc0a332af4c70a30f2e3d3246a36e1547a02e69e7258021a93a2a4994bec6c31a0a3d3659be194c58b118cb950a885ac4fa557410cb638875b14574ebf8887334e7cc0f6016257fa96c48db6f25529e1d825ce62e4f56fbfcfb8317259300f49c072814358dfb5443ec8db519ece23be603f243c7a37e16bfa58cd97e918c241caaeb53ac7898199255f798f7ba305282052858ca86de12a43b283971575a9a515519ee2193ff2c03a30b1fa16ed92abd19be0b6c7d2d31aa2a6e41cdcf8455d7c6de7b246e724eab23caa731653c634")
	//payload := quic.StrtoByte("d36165f8aca3c7ab36269e318ce627674b1a334f31eb465df52989bb4ab5a340c7344c9e5275a1474a75120ce96ef49543c2ba3ff94580e37cc47ad098bbe2698fa5e5504511c8a2e38e165391e76a93cee98244bc9b41a78d54f8f405fc796755091c82e316f1dcd3a47f6dd0b164d751f274ea530fd794f8c3c79f31b461e054c73e68b19f2eb2189a468ee32685a2e12cddd3be2a325d2d010b293e0a8549d9f1119f083d8d39610faef92003d53ebb3670a1d50e5cb0860227402f91f6fc5f9e7427474f9e6c702625c2d7deb54c9364631467244ea49d6fa4aa2a790abf8a060791064391a70808a320c9c061b1dcef41c097f8d817378fc7c63a2cc6477861ab2409ea0c7d4561c415b56ae4aacad1f7a52a33e277051465216e173cea4eaad253910b2c49a1ff0dc00a3fc5837fabd4db8e88bbec7ae6a02ca2e0fe5dd9e5bc5e549634ec6bcff13727e39a05a53672da4d3e0c3d12b9e281e822895df592c0e098f161526e01f3d90764c6c6dd3fc82bdb46f2cf9a1849d0717ae82dda562b236c566c456330e94e2bcc144361c337fbf13235361b8f3adf2c85901d851e1d6108cd354e1662665ac8e9b0d8ce012edd6c5720c9ed1fddc18d278d64252b7fac5992b54ad8bfefa70d5dbf43158cc62a509631f115b7a87f2be5d112092cde94f2fb9745c895b71cbf4b147515c41369e93d1c38ed9dd19609241fbaa63055ed639641d2aed812e065c6731ca86bbba5b971f1b194eaa04dd295cb6944d54f570aae341d0901543abcc4dd9a67e78e0f8adc61ca465ba87dad5cfaf2e210ff8f426e7d07b04133d14cf9f9a612943785f0a554a3c7f8b3e20cfd4e4572282bcf2b8b863992aa9987fa938fcd490f7130bd7121217ca461ec3cb3c77b722d8e9e8aa639dc1a03d6c226d41b2c309d185fa19a7fc8a31aab7e0cd1ed5d2a2a9d2b97e9ca457bbe91df83cde7a9b160de6c5bbcbfd480cf50774d81944096a81e6c6d396f05ef6a8b11eb4ec02eddd09d21fd920061e0236f9d6b0e43eabff53c8b844d913ce638da7cb606180c97f7be10c037c70bee0fc4e97113de2ccae64853b331ae99473ceaaa068378cfc5c17357233ac9b52e60ac837c9f9c502152ac005f8d294d0c797dde3ab34c1dff8e7a5e27f615c348483665282838ef191acbb8a411e544bdb7a63e0cab4372b8094cb82bf4827f7e89748062df139192df24b004cd74c590c493d0095a1c9be95e3d45c40ace07949ff5fa8ac7f8f0e0b65b92110601bcea56fa0fab6e470880e33f7ae5f7f4dff8d62091692093a3be2f6d99cd7330e8fc0a332af4c70a30f2e3d3246a36e1547a02e69e7258021a93a2a4994bec6c31a0a3d3659be194c58b118cb950a885ac4fa557410cb638875b14574ebf8887334e7cc0f6016257fa96c48db6f25529e1d825ce62e4f56fbfcfb8317259300f49c072814358dfb5443ec8db519ece23be603f243c7a37e16bfa58cd97e918c241caaeb53ac7898199255f798f7ba305282052858ca86de12a43b283971575a9a515519ee2193ff2c03a30b1fa16ed92abd19be0b6c7d2d31aa2a6e41cdcf8455d44c619d960ae7026663de8a9ec52cf88")
	header := quic.StrtoByte("c100000001044a4b30eb00405b4d980d67e740d1b668e76b52ca23f64addcda437e05054d512724a31b2f385a03e2dd0eff876df88c5c60c5d3d7315d9128b1c9df3e09494efb8956e6417966fd20d76d6a1e5589e423d4a91aed08131d1759881ef26ce26c84fe4447a0002")

	plaintext, err := aesgcm.Open(nil, packetnum, payload, header)
	if err != nil {
		log.Fatalf("DecryptQuicPayload is error : %v\n", err)
	}
	fmt.Printf("plaintext is %x\n", plaintext)

}
