package main

import (
	"fmt"
	"quic"
)

var localAddr = []byte{127, 0, 0, 1}

const port = 10443

func main() {
	sendinitpacket()
	//retrypacket()
}

func sendinitpacket() {
	dcid := quic.StrtoByte("7b268ba2b1ced2e48ed34a0a38")
	_, packet := quic.CreateInitialPacket(dcid, nil)
	_ = packet

	//conn := quic.ConnectQuicServer(localAddr, port)
	//recv, ptype := quic.SendQuicPacket(conn, packet)

	rawretry := quic.StrtoByte("f00000000100045306bcce4d980d67e740d1b668e76b52ca23f64addcda437e05054d512724a31b2f385a03e2dd0eff876df88c5c60c5d3d7315d9128b1c9df3e09494efb8956e6417966fd20d76d6a1e5589e423d4a91aed08131d1759881ef26ce26c84fe417b8e7e5d4becff564572c6feae8351b")
	retry, _ := quic.ParseRawQuicPacket(rawretry, true)
	retryPacket := retry.(quic.RetryPacket)

	_, retryInit := quic.CreateInitialPacket(retryPacket.LongHeader.DestConnID, retryPacket.RetryToken)

	quic.PrintPacket(retryInit, "retry init packet")

}

func retrypacket() {
	rawretry := quic.StrtoByte("f00000000100045306bcce4d980d67e740d1b668e76b52ca23f64addcda437e05054d512724a31b2f385a03e2dd0eff876df88c5c60c5d3d7315d9128b1c9df3e09494efb8956e6417966fd20d76d6a1e5589e423d4a91aed08131d1759881ef26ce26c84fe417b8e7e5d4becff564572c6feae8351b")

	retry, _ := quic.ParseRawQuicPacket(rawretry, true)
	fmt.Printf("%+v\n", retry)

	//shello := quic.StrtoByte("010001240303faac906d7be5be01d2f97311acb0f098c3e7dbb661b6987827e007913f35f442000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000d50000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100005000302683300120000002b0003020304003300260024001d002039b2d976219b39efce354d9ac5d4afb52daafd3402e0098fb547fac39007201500390041475f08d68a89670fcc19b00504800800000604800800000704800800000404800c000008010009024064010480007530030245ac0b011a0c000e01040f00200100")
	//cryptoFrame := quic.ToPacket(quic.NewQuicCryptoFrame(shello))
	//
	//destconnID := quic.StrtoByte("6e19c054")
	//keyblock := quic.CreateQuicInitialSecret(destconnID)
	//
	//initPacket := quic.NewInitialPacket(destconnID, nil, nil, 1, 2)
	//
	//initPacket.Token = quic.StrtoByte("938238c63dac3ffe79073d1945aa25d4925e7981e4f5b35488cc6367a9d8de8d3f67fa07d1f601d28f29b408cbdf73e7b8aa0821c46cd9bca7452838dffb9a5e21452fe817b4f7e01bb3546528931dcb812b59161c3d9c2ed3b4ebcb8d04d439f9b1b61decaa08315d4a")
	//initPacket.TokenLength = quic.EncodeVariableInt(len(initPacket.Token))
	//
	//paddingLength := 1252 - len(quic.ToPacket(initPacket.LongHeader)) -
	//	len(initPacket.PacketNumber) - len(cryptoFrame) - 16 - 4 - len(initPacket.Token) - 1
	//
	//// ゼロ埋めしてPayloadをセット
	//initPacket.Payload = quic.UnshiftPaddingFrame(cryptoFrame, paddingLength)
	//fmt.Printf("After padding payload is %d\n", len(initPacket.Payload))
	//
	//// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	//length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	//// 可変長整数のエンコードをしてLengthをセット
	//initPacket.Length = quic.EncodeVariableInt(length)
	//
	//headerByte := quic.ToPacket(initPacket.LongHeader)
	//fmt.Printf("header is %x\n", headerByte)
	//// c100000001046e19c05400
	////
	//// set Token Length
	//headerByte = append(headerByte, initPacket.TokenLength...)
	//headerByte = append(headerByte, initPacket.Token...)
	//headerByte = append(headerByte, initPacket.Length...)
	//headerByte = append(headerByte, initPacket.PacketNumber...)
	//
	//fmt.Printf("header is %x\n", headerByte)
	//
	//enctext := quic.EncryptClientPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
	//_ = enctext

}
