package main

import (
	"quic"
)

var localAddr = []byte{127, 0, 0, 1}

const port = 10443

func main() {
	sendinitpacket()
}

func sendinitpacket() {
	//dcid := quic.StrtoByte("7b268ba2b1ced2e48ed34a0a38")
	//_, packet := quic.CreateInitialPacket(dcid, nil, 0)
	//quic.PrintPacket(packet, "packet")

	//conn := quic.ConnectQuicServer(localAddr, port)
	//recv, ptype := quic.SendQuicPacket(conn, packet)

	rawretry := quic.StrtoByte("f00000000100045306bcce4d980d67e740d1b668e76b52ca23f64addcda437e05054d512724a31b2f385a03e2dd0eff876df88c5c60c5d3d7315d9128b1c9df3e09494efb8956e6417966fd20d76d6a1e5589e423d4a91aed08131d1759881ef26ce26c84fe417b8e7e5d4becff564572c6feae8351b")
	retry, _ := quic.ParseRawQuicPacket(rawretry, true)
	retryPacket := retry.(quic.RetryPacket)

	// ServerからのRetryパケットのSource Connection IDをDestination Connection IDとしてInitial Packetを生成する
	_, retryInit := quic.CreateInitialPacket(retryPacket.LongHeader.SourceConnID, retryPacket.RetryToken, 1)

	quic.PrintPacket(retryInit, "retry init packet")
	//recv, ptype := quic.SendQuicPacket(conn, packet)

}
