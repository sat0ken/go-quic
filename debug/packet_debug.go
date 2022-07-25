package main

import (
	"fmt"
	"golang.org/x/crypto/curve25519"
	"quic"
)

func _() {
	dcid := quic.StrtoByte("ab6c6b3af832e64beaaf8b30")
	keyblock := quic.CreateQuicInitialSecret(dcid)
	quic.PrintPacket(keyblock.ClientIV, "ClientIV")
	chello := quic.StrtoByte("0600413e0100013a03030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000eb0000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100014001211717569632d6563686f2d6578616d706c6500120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74003900484b200eabdc497fa253edabe08d08a9739c0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00200100")

	var init quic.InitialPacket
	initPacket := init.NewInitialPacket(dcid, nil, nil, 0, 2)
	paddingLength := 1252 - len(quic.ToPacket(initPacket.LongHeader)) -
		len(initPacket.PacketNumber) - len(chello) - 16 - 4
	// set Crypto Frame(client hello)
	initPacket.Payload = quic.UnshiftPaddingFrame(chello, paddingLength)
	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = quic.EncodeVariableInt(length)

	headerByte := quic.ToPacket(initPacket.LongHeader)
	// set Token Length
	headerByte = append(headerByte, initPacket.TokenLength...)
	//headerByte = append(headerByte, initPacket.Token...)
	headerByte = append(headerByte, initPacket.Length...)
	headerByte = append(headerByte, initPacket.PacketNumber...)
	quic.PrintPacket(headerByte, "header")

	enctext := quic.EncryptClientPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
	//quic.PrintPacket(enctext, "enc payload")

	packet := headerByte
	packet = append(packet, enctext...)
	protectPacket := quic.ProtectHeader(len(headerByte)-2, packet, keyblock.ClientHeaderProtection)
	quic.PrintPacket(protectPacket, "rotect packet")

}

func main() {
	fmt.Println("--- decryptHandshake ---")
	destconnID := quic.StrtoByte("400c4c85")
	// destination connection id からキーを生成する
	keyblock := quic.CreateQuicInitialSecret(destconnID)
	_ = keyblock

	handshakeMessages := quic.StrtoByte("0100013a03030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000eb0000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100014001211717569632d6563686f2d6578616d706c6500120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74003900484b200eabdc497fa253edabe08d08a9739c0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00200100")
	handshakeMessages = append(handshakeMessages, quic.StrtoByte("020000560303000000000000000000000000000000000000000000000000000000000000000000130100002e002b0002030400330024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")...)

	privateKey := quic.StrtoByte("0000000000000000000000000000000000000000000000000000000000000000")
	serverPubkey := quic.StrtoByte("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")
	commonKey, _ := curve25519.X25519(privateKey, serverPubkey)

	tls13Keyblock := quic.KeyscheduleToMasterSecret(commonKey, handshakeMessages)

	rawHandshakePacket := quic.StrtoByte("e7000000010004a37891c24454d823afb0f3211fc6d29eb84e2ece6d2b101195bf4467cfa8e03d90c4a65cadd8945314dcfeedeedb4fe745c894b50064062b8f8ef330f343e6bdd22a7bdc3c0e0bd26be8c766edf68487209fa59b065b2cdac9707d576954933ddfdb72328a2f5bf78760994dd993597998fb402aeb0d0a2720871e6b77bf1ae676644ab8f88b7d018a7015373518c65447c29d2844a7385a7b51cab18cc67916baa1a62d3e31f6e5c7d3af48594d8f60c88ca72502ee5442e86be1304a9e948f72af8d4a1e5d9f2714c214a721592c1548a03bd3ede0a0b85476d49201d76632479402e1a8ec96a77a4794c3d7f377c51c77b5ec7b7682bf3dae8aeeb807ad51582f48026e07f357430882b2cdc1cac8c0b0d05fbe16f810702d5892d626ff8b03b7bb98df1df805b43d5a3b601ce3a981905c536a0570d412e9c6791217d6495265af1a54cba999f082836ed4f085d57e8cfe593deade8a649f02add9b3d63fcaa37cbb07547ed34cbe2a9d18b3a9841ecc6d138e0cfeada586761a6a9a0a5ce70797f281b22a45cfb6927c362fd5b30e0a19fd3ef59fbd5265632b2ea3f736ddfd7f3842e214eb44aeed4566db5342ea612108abb0eeb859eb3e8bbe8b4b005a20442ce678715626edc3f7201b042411c5fc30204e331e2592dd62c9182a57a8a1534bbb323e831e7c8407e31761228f34eb8960d1118d8c26184b401ac48d3ef7ec1d486138db3f15a5cf838f8faf10a6182baec3f18188990daa24b22b0374650c161ab45f2b7faec3f0825a5b706693df3c3fac66844972ec3a4d8f12d5bac89aac6ced065a2773c38b58b7476bd9a6b2bf40a89002a258c2f54ccdc0c98d2a1b4c6b2d0cbaa08e5bec11a79e9012425e23ee94ebaf2ebe02f2c95c3a602183bfac82c9c7225a217dc6df08db99745b422a3b8f5febbdad389accf886bc092c5b1cd6df2a8e44a37c26fea8ac9926248c2c32cbbe8242b3cf8548ca24d5317116a6387abd82b1402026af5ac4864040d67f59ac84139166a266e256d55f94e289e416f3f3efd601c9ebe58a3a0db096eba70952df26b7b06613c211683c88ae6c4dbec2e279d518edfd06a952a837507d4fccb9f8a4ed6ceff1a7e9ac58376258e2a1277206d0de9408340168bf9e2a3489f80a977c571c843bc4723bd5fe74616aa672565a37e590c0febee31b5dd12eb9ba6cd392451b49a929efc21913234f9462a664108b41418fcb9d00fa9471c0ef99273f4b10fdcb85e99f741f3f53b68bb18324f383dc4892fd3b8e4d3357957d195e8fd6920bae158d57c0a3f0ad6eb9114dbfc4f7a7d691ba9d03a8cebd4b2037fc69f52fd4b269b7085e287859e0eb5bf37019eb2c81c9496ecb37f838f308ac0a800adfe586bf3da589685408f75e436d99a5a244a755e9503bf224083ed1bf201531af29de7b33b7eee75eb9a3404efc172c7ecc045f64da307e289f99d399582a829b2c59b01d52849782eb2a65094ce06b41d1d3c7d195555bba11dd76626d7f7321d22a4face20e215f2a39d37a11f79fabe99afa02728a78068a61a56e90a06b4703")
	//rawHandshakePacket := quic.StrtoByte("cb000000010004a37891c200407530cc4a7dac5a2870abcef4d599d9ae9fb35835b0b75d16c3eea68730928a3c78567f3bb0f448cc3ee26d554400a1d63686225c41e7b4041ddaf00486de22c863323407a55b1840d24415cad5ad2fd773e1de8e1b4035083cf0b0301b9f0d04b295d06ac6149d5c24eed9b8290c465f6906bde962f1")
	parsed, _ := quic.ParseRawQuicPacket(rawHandshakePacket, true)

	rawHandshake := parsed.(quic.HandshakePacket)
	startPnumOffset := len(rawHandshakePacket) - len(rawHandshake.Payload) - 2

	unprotect, _ := quic.UnprotectHeader(startPnumOffset, rawHandshakePacket, tls13Keyblock.ServerHandshakeHPKey)
	handshake := unprotect.(quic.HandshakePacket)
	headerByte := quic.ToPacket(handshake.LongHeader)
	headerByte = append(headerByte, handshake.Length...)
	headerByte = append(headerByte, handshake.PacketNumber...)

	quic.PrintPacket(headerByte, "unprotect header packet")

	serverkey := quic.QuicKeyBlock{
		ServerKey: tls13Keyblock.ServerHandshakeKey,
		ServerIV:  tls13Keyblock.ServerHandshakeIV,
	}

	plain := quic.DecryptQuicPayload(handshake.PacketNumber, headerByte, handshake.Payload, serverkey)
	quic.PrintPacket(plain, "plain text")

}
