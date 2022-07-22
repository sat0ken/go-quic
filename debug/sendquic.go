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
	//header, initPacket := quic.NewQuicLongHeader(destconnID, nil, 0, 2)
	var initPacket quic.InitialPacket
	initPacket = initPacket.NewInitialPacket(destconnID, nil, nil, 0, 2)

	paddingLength := 1252 - len(quic.ToPacket(initPacket.LongHeader)) -
		len(initPacket.PacketNumber) - len(cryptoFrame) - 16 - 4

	// ゼロ埋めしてPayloadをセット
	initPacket.Payload = quic.UnshiftPaddingFrame(cryptoFrame, paddingLength)
	//fmt.Printf("paddingLength is %d\n", paddingLength)
	fmt.Printf("After padding payload is %d\n", len(initPacket.Payload))

	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = quic.EncodeVariableInt(length)

	headerByte := quic.ToPacket(initPacket.LongHeader)
	// set Token Length
	headerByte = append(headerByte, 0x00)
	headerByte = append(headerByte, initPacket.Length...)
	headerByte = append(headerByte, initPacket.PacketNumber...)

	fmt.Printf("header is %x\n", headerByte)

	enctext := quic.EncryptClientPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
	//fmt.Printf("enctext is %x\n", enctext[0:16])

	packet := headerByte
	packet = append(packet, enctext...)

	//fmt.Printf("header is %x, %+v\n", quic.ToPacket(header), header)
	protectPacket := quic.ProtectHeader(len(headerByte)-2, packet, keyblock.ClientHeaderProtection)
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

	var initPacket quic.InitialPacket
	initPacket = initPacket.NewInitialPacket(destconnID, nil, nil, 1, 2)

	initPacket.Token = quic.StrtoByte("938238c63dac3ffe79073d1945aa25d4925e7981e4f5b35488cc6367a9d8de8d3f67fa07d1f601d28f29b408cbdf73e7b8aa0821c46cd9bca7452838dffb9a5e21452fe817b4f7e01bb3546528931dcb812b59161c3d9c2ed3b4ebcb8d04d439f9b1b61decaa08315d4a")
	initPacket.TokenLength = quic.EncodeVariableInt(len(initPacket.Token))

	paddingLength := 1252 - len(quic.ToPacket(initPacket.LongHeader)) -
		len(initPacket.PacketNumber) - len(cryptoFrame) - 16 - 4 - len(initPacket.Token) - 1

	// ゼロ埋めしてPayloadをセット
	initPacket.Payload = quic.UnshiftPaddingFrame(cryptoFrame, paddingLength)
	fmt.Printf("After padding payload is %d\n", len(initPacket.Payload))

	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = quic.EncodeVariableInt(length)

	headerByte := quic.ToPacket(initPacket.LongHeader)
	fmt.Printf("header is %x\n", headerByte)
	// c100000001046e19c05400
	//
	// set Token Length
	headerByte = append(headerByte, initPacket.TokenLength...)
	headerByte = append(headerByte, initPacket.Token...)
	headerByte = append(headerByte, initPacket.Length...)
	headerByte = append(headerByte, initPacket.PacketNumber...)

	fmt.Printf("header is %x\n", headerByte)

	enctext := quic.EncryptClientPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
	_ = enctext

}
