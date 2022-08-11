package main

import (
	"fmt"
	"quic"
)

var localAddr = []byte{127, 0, 0, 1}

const port = 18443

func main() {
	sendinitpacket()
	//fraghandshake()
	//handshakePacket()
}

func sendinitpacket() {
	dcid := quic.StrtoByte("7b268ba2b1ced2e48ed34a0a38")
	tlsinfo, packet := quic.CreateInitialPacket(dcid, nil, 0)

	conn := quic.ConnectQuicServer(localAddr, port)
	recv := quic.SendQuicPacket(conn, packet)

	retryPacket := recv[0].Packet.(quic.RetryPacket)

	// ServerからのRetryパケットのSource Connection IDをDestination Connection IDとしてInitial Packetを生成する
	tlsinfo, retryInit := quic.CreateInitialPacket(retryPacket.LongHeader.SourceConnID, retryPacket.RetryToken, 1)

	// ここでInitial PacketでServerHelloが、Handshake PacketでCertificateの途中まで返ってくる
	// recvhandshake[0]にInitial Packet(Server hello), [1]にHandshake Packet(Certificate~)
	recvhandshake := quic.SendQuicPacket(conn, retryInit)

	// Initial packet を処理する
	initPacket := recvhandshake[0].Packet.(quic.InitialPacket)
	// [0]にACK, [1]にCRYPTO(ServerHello)が入る
	qframes := initPacket.ToPlainQuicPacket(initPacket, recvhandshake[0].RawPacket, tlsinfo)

	var shello quic.ServerHello
	tlsPackets, isfrag := quic.ParseTLSHandshake(qframes[1].(quic.CryptoFrames).Data)
	if !isfrag {
		shello = tlsPackets[0].(quic.ServerHello)
	}
	commonkey := quic.GenerateCommonKey(shello.TLSExtensions, tlsinfo.ECDHEKeys.PrivateKey)

	tlsMessages := tlsinfo.HandshakeMessages.ClientHello
	// server hello を追加
	tlsMessages = append(tlsMessages, qframes[1].(quic.CryptoFrames).Data...)
	// 鍵導出を実行
	//tls13Keyblock := quic.KeyscheduleToMasterSecret(commonkey, tlsMessages)
	tlsinfo.KeyBlockTLS13 = quic.KeyscheduleToMasterSecret(commonkey, tlsMessages)

	// Handshake Packetを処理
	handshake := recvhandshake[1].Packet.(quic.HandshakePacket)
	frames := handshake.ToPlainQuicPacket(handshake, recvhandshake[1].RawPacket, tlsinfo)

	fmt.Printf("Handshake packet CryptoFrames is %x\n", frames[0].(quic.CryptoFrames).Type)
	fmt.Printf("Handshake packet CryptoFrames's Data is %x\n", frames[0].(quic.CryptoFrames).Data)

	tlsPackets, frag := quic.ParseTLSHandshake(frames[0].(quic.CryptoFrames).Data)
	//fmt.Printf("tlsPackets %+v\n", tlsPackets)

	var fragPacket []quic.ParsedQuicPacket
	// パケットが途中で途切れてるなら次のパケットを読み込む
	if frag {
		fragPacket = quic.ReadNextPacket(conn)
	}

	fraghs := fragPacket[0].Packet.(quic.HandshakePacket)
	startPnumOffset := len(fraghs.ToHeaderByte(fraghs, false)) - 2
	unpPacket := quic.UnprotectHeader(startPnumOffset, fragPacket[0].RawPacket, tlsinfo.KeyBlockTLS13.ServerHandshakeHPKey)
	unpFragmentHS := unpPacket[0].Packet.(quic.HandshakePacket)

	plain := quic.DecryptQuicPayload(unpFragmentHS.PacketNumber, unpFragmentHS.ToHeaderByte(unpFragmentHS, true), unpFragmentHS.Payload, tlsinfo.QuicKeyBlock)
	fmt.Printf("fragment packet plain is %x\n", plain)

}

func handshakePacket() {
	destconnID := quic.StrtoByte("5306bcce")
	// destination connection id からキーを生成する
	keyblock := quic.CreateQuicInitialSecret(destconnID)

	// local-quic-go.pacpng No.4のパケット
	h := quic.StrtoByte("c70000000100044a4b30eb0040754e968ed438dd5ba1b6cafef2cb9c84ee9bc9efc838f64b7e4ac53396ff7aaa3fdc1fa2b94326d8141d41ffd5787f21f5f54e7a1c9ad9501d108463a6e272c7f1263aa23560a00a5ad5d41c0c79239f18a138a0bb8270e0d9dbd369f6ce1ce5f01d6176726a9046b539457f72df7081f0b27c01e275ef0000000100044a4b30eb44544cd3b74f603556b6c49d4a126b108397a9b59e8d3b7f1843bf9fb1a09ed68f2d858bb5c16149c6f37a938c589a9ed8ae9c4342de373fc48c97a3d37c9db6d7b59b7610e34628062b8c97efa6675e43e266650589d360b45cd05878c30955b7e08ac0b7b90e6eb2c356d8806ab1389748b710141b008f43969e31f72485257ab7c938d95f08d0315e3d8529855b5ffb32795f9c39da4180e54748669fe7939b2f17a1f3e53d8bb025ac4a99e4afda8ad45ea41eff53b2f73358e561545af1622412a29b71d51e3643a09579d417900f779861d1581b5aaddfa0b062bb8b1087121608f5ff055fe84c37a8d3f1648dcb96f01cb021a91d88e28283cbddc649658692f1598bf78146bdcfd2e20e61801b5616cac088f594cb92b0a5b1d567cf97f1bd7cfdeead4e2ca4da15a1bcf50bc032393a656cc5a1556be9bde6f00770c8329a530eef3a4c8327fde355a09c88759c889b40bc32c8301b911b2401478ea2b6ec05008c71b4b7a88f423b5672286c092dcc6dd66a530e46a99cd426567616aa9f5c7e96d0bdf638730c6e04d71836ea7820cbc1b52ff923238a0df00533b819b89f5f89b22c44f178cdaf6840908f5eb3cbe03778b6038f4ca689e9501174dc7cbe9db91afe08c604d931c20bcbde95e90225b49a4d95cc7ce60762e35ba9af851eac9cc17a181baaeea374c0ca9875f9b08880d84c0f2ae1cc98dc588eb282448777bda611b53e8ef6ca8350ea0a4dd7bf05ae1d31bb98b7c85660104b15a2970e9df891a0a89ba6846ec091a95d82a9e88defc5538bca59f47e1be59cbfd7bdeb03bca81bdc1b80f5104c66a7c1b6290e5893938e3f9345b8637a0d22e68d1527dff1af299e9d3faa40878dc1c9b829a7d367aa89250f6c9ca30f8fb3af171cb6a6ce1192df091ec31c5c778d28394a9e5821a64218b254129969a3baecd9a430e243aa20af50194bec23aecd5edcf3c9e719a6d7dd5a3b3fedb7ad5cbe40bce0d0d1457ae06242a282e39a41a19963f9140323c35458c3278a3d90c373a6ae95cb94a81ce2ce6295dee518390a856ba1bade91e8c0ce585509cce067eabb83863a70e534aa69dcebdfbdb3e6e50f1558df5a9992355598f19f66612cc6622c91e5f6e3e260fd06bfd4f0b96a0f700ee3d39c1610673d87df7d2efceb06d1e1128d98265f0055978485db145f320e8ecda45979a4c7553f6cfa84da7ddf1cf9c00a975ab747844dc25d5061a4fb7d317195ce76ffedb9a8e62d1401a12682796f622b72f17800bea5499aa628f6d0062ca8f82224732e79b72be159d150b9fdc05c56cd007a92ad21c524dc333436e9fb89a333524a76c9cf09dab065161e8c93e8a1e6830b4e1800562bfb93dcd0ae52f433be365f8bcc2ab3101ac37b0e618f532fee4a2edbf6013d2de13b0600fc246e1de872fdad123816dd8d8a0735d9a444c7d6a4699919eac9f0b21356e860e34078c781375cf1304a9337e21301186e5a73165c2a2df71749a817ee05618230d2742fe578e421a2369111c06c6a74f866302b40b9d1dd93dfe990a382f5b73c91f7")
	// parsed[0]にInitial Packet(Server hello), [1]にHandshake Packet(Certificate~)
	parsed := quic.ParseRawQuicPacket(h, true)
	initPacket := parsed[0].Packet.(quic.InitialPacket)
	startPnumOffset := len(initPacket.ToHeaderByte(initPacket, false)) - 2

	unpInit := quic.UnprotectHeader(startPnumOffset, parsed[0].RawPacket, keyblock.ServerHeaderProtection)
	init := unpInit[0].Packet.(quic.InitialPacket)

	// Initial Packetを復号
	plain := quic.DecryptQuicPayload(init.PacketNumber, init.ToHeaderByte(init, true), init.Payload, keyblock)
	qframes := quic.ParseQuicFrame(plain)

	var shello quic.ServerHello
	tlsPackets, isfrag := quic.ParseTLSHandshake(qframes[1].(quic.CryptoFrames).Data)
	if !isfrag {
		shello = tlsPackets[0].(quic.ServerHello)
	}

	fmt.Printf("server hello is %x\n", qframes[1].(quic.CryptoFrames).Data)

	privateKey := quic.StrtoByte("0000000000000000000000000000000000000000000000000000000000000000")
	commonkey := quic.GenerateCommonKey(shello.TLSExtensions, privateKey)

	chello := quic.StrtoByte("0100013003030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000e10000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100014001211717569632d6563686f2d6578616d706c6500120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b740039003e420b041fad788e0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00200100")

	// server hello を追加
	chello = append(chello, qframes[1].(quic.CryptoFrames).Data...)
	// 鍵導出を実行
	tls13Keyblock := quic.KeyscheduleToMasterSecret(commonkey, chello)

	handshake := parsed[1].Packet.(quic.HandshakePacket)
	startPnumOffset = len(handshake.ToHeaderByte(handshake, false)) - 2

	unpPacket := quic.UnprotectHeader(startPnumOffset, parsed[1].RawPacket, tls13Keyblock.ServerHandshakeHPKey)
	unpHandshake := unpPacket[0].Packet.(quic.HandshakePacket)
	serverkey := quic.QuicKeyBlock{
		ServerKey: tls13Keyblock.ServerHandshakeKey,
		ServerIV:  tls13Keyblock.ServerHandshakeIV,
	}

	plain = quic.DecryptQuicPayload(unpHandshake.PacketNumber, unpHandshake.ToHeaderByte(unpHandshake, true), unpHandshake.Payload, serverkey)
	fmt.Printf("plain is %x\n", plain)

	frames := quic.ParseQuicFrame(plain)
	fmt.Printf("%x\n", frames[0].(quic.CryptoFrames).Type)
	fmt.Printf("%x\n", frames[0].(quic.CryptoFrames).Data)

	tlsPackets, frag := quic.ParseTLSHandshake(frames[0].(quic.CryptoFrames).Data)
	fmt.Printf("isfrag %v\n", frag)
	fmt.Printf("tlsPackets %+v\n", tlsPackets)

	// frag が true なら recvをもう1回呼んで次のパケットを読み込む

}
