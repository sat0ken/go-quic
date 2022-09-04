package main

import (
	"fmt"
	"golang.org/x/crypto/curve25519"
	"quic"
)

func main() {
	header := quic.CreateHTTP3HeaderByteArray()
	fmt.Printf("header is %x\n", header[2:])
}

func _() {
	donetokencrypto := quic.StrtoByte("1e07404a2978ecd70c1e8f43c7ca9dc761f7fc5655ab76a197624013c4f6c08e703fb954359b06ef89050fe26cdfe06da7bba88d0d72734add57df1c4bf532e82a502e31f620185fd3e8480161920600409c0400009800093a8000000000000083b7c152e121f5da3cd63e2fba7aa53abf0000000000000000000000000000000039a907d3339fba9b9870b9bec1fbcc9088811c4771cc73b619312874029edfcc3c2baeda0f918d09c12335dc38b6d8ce0a68c34c695602a38676bb7a11611e1442d4233e57ffa1f81244d77cb4b1bef2c24b32d06a8eb7b8917eb944d97c90a51f8e030008002a0004ffffffff")
	frames := quic.ParseQuicFrame(donetokencrypto, 0)

	for _, v := range frames {
		fmt.Printf("frames is %+v\n", v)
	}

	tlsTicket := quic.StrtoByte("0400009800093a8000000000000083b7c152e121f5da3cd63e2fba7aa53abf0000000000000000000000000000000039a907d3339fba9b9870b9bec1fbcc9088811c4771cc73b619312874029edfcc3c2baeda0f918d09c12335dc38b6d8ce0a68c34c695602a38676bb7a11611e1442d4233e57ffa1f81244d77cb4b1bef2c24b32d06a8eb7b8917eb944d97c90a51f8e030008002a0004ffffffff")
	ticket, _ := quic.ParseTLSHandshake(tlsTicket)
	fmt.Printf("ticket is %+v\n", ticket)
}

func _() {
	var short quic.ShortHeader
	var tlsinfo quic.TLSInfo
	tlsinfo.KeyBlockTLS13.ServerAppKey = quic.StrtoByte("331beac1eeeb832ab276c16be3aa66a7")
	tlsinfo.KeyBlockTLS13.ServerAppHPKey = quic.StrtoByte("8ae6c781133755a0b1ebca7bcaff0a80")
	tlsinfo.KeyBlockTLS13.ServerAppIV = quic.StrtoByte("ac7cead721597ace67461400")

	shortpacket := quic.StrtoByte("4d042a82c35c4e347b0f3ec74441134649c03f8b995e8e3fb9cf89c716297ef3485d42c03797e10bc19f9c2d866be377d1694e3c19654b3f14132f026baee994c4322c097365a7c6ce91d53691ba059f42ac553500ab073f39a40c3316c3a6d8")
	parsed, recvPacket := quic.ParseRawQuicPacket(shortpacket, tlsinfo)
	if len(recvPacket) == 0 {
		short = parsed.Packet.(quic.ShortHeader)
	}
	fmt.Printf("short packet header is %x\n", short.ToHeaderByte(short))
	frames := short.ToPlainQuicPacket(short, tlsinfo)
	fmt.Printf("NewConnectionID is %+v\n", frames[0])
}

func _() {
	var tlsinfo quic.TLSInfo
	destconnID := quic.StrtoByte("eccb57e0")
	tlsinfo.QuicKeyBlock = quic.CreateQuicInitialSecret(destconnID)
	tlsinfo.HandshakeMessages = quic.StrtoByte("0100012103030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000d20000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100005000302683300120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b740039003e420b041fad788e0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00200100")

	var parsed quic.ParsedQuicPacket
	packet := quic.StrtoByte("c8000000010004b4abf12b004075431a6d8997a12c4bac24e3482b2da41d5a4582dd827474c98f6f4f9168dc1ee760576593ce2a5c31a0cf5a311855fb2488a4ea293ab179521beb0bbcffb233e61ce958ea42f307769334fdcf38f5f461152157c4d0ba2990b5a7653ee1565f4b087cdeabcdb5a01fc4a636a26865ccd185e20910f1ed000000010004b4abf12b44542c2678293bfe7d9d6272c8de509b787460435c16f3193e1ca76f203a1118b07632b92372decb39babcc5b286dc90f3a1ca8d21a3aa1693d5a8ca19fe5722ac4374839269c69aa2ed04674bd80f41d3c6691a7d637d4f5beef0c93226ce851d96934c24902eb796d1304609c925a331b0e4cb8c2e40171560f290b6ddc69994681ab9069b7ecadf99b99643fce8a435b32d2dc36a1ec8d5515f8625cc32f75b29ec174edeef10b4f9f569c70e9b64fd5f2ee47e80cc41aa98f7238003be38d0cf80ceb48f441319e5af0ba5186bce9cc746b64eed750ddbc08e29dc0d77437eccdf99bd84a8b04894fea4579d1e5c1747dabb6132f6a3d0b8ab2b75486ec21a8599d2aa22472e3e75837515931309e411c776b9612ad17c8f516ea4c565d0e075934478c1ef7abf9aa8f424e5af9210ace79a813de309ff9588bdba580f45be41f080cd16317bfc16c8a4485e54f97991988f25b136c1b48b0ffd26c03bf30824603754fbdd8d088d8404b90dc5ef046675f7bc373a1a1d9839914de5247a7d18fda31bd004561f1cb54b7a49834dfd89195a35155f79f4f4aaf7e8a74be9dca0ca6a6d65a2c1490373d037f37ec1215636f89eddc0188c363f9ef5a16ca044b1f1b2568f85cc12e7ce2931bb663a8f530ed0539ae6d48bd76718d781e9f83b78864e3b3bf3312a3e3d886bf0bcf08bee7de6cbed9c2ebcea8bbf8ff30e080cd013d7ef8e07f1aa626eaff532b5f86c3e553b7cc69de0918a734df17781ff858e70e37d84843a3843a805a4b590665714333d35d58952d4cae34eac4a9322f58ef079f17dc5fa8fd9c3fd87427b03f3eba8b7520b31a4bdd885723b7d063d6b943b25a67a90dd574ac2332de960fa6045f41e7ab218bcd341f9283f38dcb264f750817f3258c1c916afbe391440c29622effc0a020a6a99a63d5f8247a1b537dad0ad73d9324b6a9ce4517cea68946f4028982d25ed5a648ccaae4c01d0c186252d9daff2468e55ef011d9a2ec8c9ba32143105210ca0acce0722d9177426d8dafc6bb7ce73c62defca33eb774cf99d819849163fbda4632f668e213df67ddf6c065039b56b1867dde8da018e869966df7934d43b930c6bce55364075c46916f001558a9f669df50e19a2a6dc130bf9b6c953ebdba68016ea8717955e11a2cedb320c7461c817aa92c6f52430e8b9578e6a26ae980557f4cc881fd5fb76cf7e590f13e9c87d086caa65dfd0eaba483ecf4337b00c678f91ce99b6671007779f085852ac56661a2649fe8f6003bb43f6c66e889db6127f9f456b0333e66d148bc8f9a34be930f82484c9b496ecce51f4631387db95c1a58e042b09d85c960b0a36ed9d272a700b6dc5797c1f46bc1f8762247d38d0b8c2b51a5b319324d71e7b23fe30388e1fd67a244105df7b564453e585e7940ae858463f85b3049ac940e854f866aab835aa7d3969a33f89146868bc9669e0b4f106888a4b13d2c3b2615da3d48b9c281dea3699e088e5be7d65243a0627e8929a635be2f5565778cdbc96150a13cc6ec85dccba8dee5f45a758fa4ba42d9dc1")
	parsed, packet = quic.ParseRawQuicPacket(packet, tlsinfo)

	init := parsed.Packet.(quic.InitialPacket)

	plain := quic.DecryptQuicPayload(init.PacketNumber, init.ToHeaderByte(init), init.Payload, tlsinfo.QuicKeyBlock)
	fmt.Printf("plain packet is %x\n", plain)
	frame := quic.ParseQuicFrame(plain, 0)

	var shello quic.ServerHello
	shelloPacket, frag := quic.ParseTLSHandshake(frame[1].(quic.CryptoFrame).Data)
	if !frag {
		shello = shelloPacket[0].(quic.ServerHello)
	}

	tlsinfo.ECDHEKeys.PrivateKey = quic.StrtoByte("0000000000000000000000000000000000000000000000000000000000000000")
	commonkey := quic.GenerateCommonKey(shello.TLSExtensions, tlsinfo.ECDHEKeys.PrivateKey)
	// server hello を追加
	tlsinfo.HandshakeMessages = append(tlsinfo.HandshakeMessages, frame[1].(quic.CryptoFrame).Data...)
	// 鍵導出を実行
	tlsinfo.KeyBlockTLS13 = quic.KeyscheduleToMasterSecret(commonkey, tlsinfo.HandshakeMessages)

	fmt.Printf("remain packet is %x\n", packet)
	parsed, packet = quic.ParseRawQuicPacket(packet, tlsinfo)
	var handshake quic.HandshakePacket
	if len(packet) == 0 {
		handshake = parsed.Packet.(quic.HandshakePacket)
	}
	fmt.Printf("unprotect header is %x\n", handshake.ToHeaderByte(handshake))
	keyblock := quic.QuicKeyBlock{
		ServerKey: tlsinfo.KeyBlockTLS13.ServerHandshakeKey,
		ServerIV:  tlsinfo.KeyBlockTLS13.ServerHandshakeIV,
	}
	plainHandshake := quic.DecryptQuicPayload(handshake.PacketNumber, handshake.ToHeaderByte(handshake), handshake.Payload, keyblock)
	frame = quic.ParseQuicFrame(plainHandshake, 0)
	tlspacket, frag := quic.ParseTLSHandshake(frame[0].(quic.CryptoFrame).Data)
	fmt.Println(frag)
	fmt.Printf("tls packet is %+v\n", tlspacket)

}

func _() {
	var tlsinfo quic.TLSInfo
	destconnID := quic.StrtoByte("56c3d6df")
	tlsinfo.QuicKeyBlock = quic.CreateQuicInitialSecret(destconnID)

	//fmt.Printf("key is %x, iv is %x\n", tlsinfo.QuicKeyBlock.ServerHeaderProtection, tlsinfo.QuicKeyBlock.ServerIV)
	//
	//// InitialPacketのServerHello
	//handshake := quic.StrtoByte("ca00000001000420825dbd004075c6e91f76b14330efe25ac215d2a01810cf2a469d2ca772a61bfa9499d5498f24f04431c672cc988baedfbff9e77fba2a6961e34c9605786abf8518f3dbe183c85bae9c1a5af382e8bdd5eb768d920edcc5ed8e94e0148ebb0236349832f9b646f91be74b203a6c769a5e80983863fb10e95176b9fe")
	//packet := quic.ParseRawQuicPacket(handshake, tlsinfo)[0].Packet.(quic.InitialPacket)
	//fmt.Printf("header is %x\n", packet.ToHeaderByte(packet, true))
	header := quic.StrtoByte("c100000001000420825dbd0040750000")
	payload := quic.StrtoByte("02010000000600405a020000560303000000000000000000000000000000000000000000000000000000000000000000130100002e002b0002030400330024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")

	enc := quic.EncryptServerPayload([]byte{0x00}, header, payload, tlsinfo.QuicKeyBlock)
	pnOffset := len(header) - 2

	header = append(header, enc...)
	fmt.Printf("enc is %x\n", header)

	protect := quic.ProtectHeader(pnOffset, header, tlsinfo.QuicKeyBlock.ServerHeaderProtection, true)
	fmt.Printf("protected packet is %x\n", protect)

	parsed, _ := quic.ParseRawQuicPacket(protect, tlsinfo)
	init := parsed.Packet.(quic.InitialPacket)
	fmt.Printf("Init packet is %+v\n", init)
	fmt.Printf("header byte is %x\n", init.ToHeaderByte(init))

	frame := init.ToPlainQuicPacket(init, tlsinfo)
	fmt.Printf("frame is %+v\n", frame[0])
	fmt.Printf("frame is %+v\n", frame[1])

}

func _() {

	// Handshake packet
	//p := quic.StrtoByte("ea0000000108fa37e3149ef0ef7c140000000000000001e67fded7f4245ddd27e210314425b4c444fb10737266f1283b63c5910b904f3e300ac9f70a60fb9b43afc0f035296132d8283dd0d55ad92212ae4f8f4ecab64441e161e29c6634ce9a6a9fef4d5dcdcb9c3608f1f5e384e87aa0def88d9af845192984fb6d0a743d297ab92d790dec5d7751214192cc626eb435df645179d91025d0d1a754c16e9433934b8789759eac00573987c9c59afbdfea031d98591317647f635d7f46127a22b8d5ec57707378d147b90f42a61fd83f456e86d98f8e36fd54f15886cadd6c3228ff1a06ef8d4e95a7472f60fe384cca009809374925d7d3b7eb4bb0042f8fb7827e005a9f9fb5d41660c9ef64ad018fd1d91d5985fb7563d19b31972360c21cda5ee6c8ac13cebd48749efa73c4415f35aae3d8e68f8492c476aab6ad7fd078c7b0efd023879fa6ba601c29f2dd7586f43a24eb839803d2da9d2c8f59ab383064916d29b5019a563b32c8fe94ada4460e0736f2d6d57308d2faaee7bf2f27dd10118d2a07bc39057af854fc30c0c9e6105e83dca582d5b335be229e6b1baf71b9aef47260601ff8255f5a882e092f1bbfdea1dd113565c741d80a9ac1dc0babe7f20307e91f2dfaad0452de085416f5c009b888e496ffaecba02fb5ba017803009e2288fc7a456fadea2633becded54a65e3ab11d620bbcf19bab3abd36a0bc8fe29723b355258e5c8004e44a35a3e64e052649ffa9c63b80f04d4e4bce0a8af56ed8979af2e1b8392f38e2175a7089897a5dd1f1b7e3ecbda73cc409bd6e78608bd25b37a68bef5b6521ba430954ba5ab4974b78c025cd3b48cb18fa3a38b1dc9290369de1907a4db5f28cf8fa1bb68ec3b935583f90a125802d94a40bfe91df333b97a5797102a49c214c0216b816d2318f03b051572ce9d1a4a3bdbcc9605eb23fee78909543037fdd6485a74e485897e8736b75cf8a89f2cf4081151b6b7786df5b12bfa8596dfcea2ce83501ee3f34a22f446f44ebbaed193c793782c8f46920cab8bbfd187cd64b42150bf03fdac6b8ae189566dcba14450cf05c50d049da0b90338ef1982785d2dca934948ca551b9bc7431491a06583383415aaf54d5cb039b5d425456d41effbd5a0b7862cf690ec960a02fc47b4d34234f0189df2acddba74095e73f016ba3525c1706e9539250f60a48835c4daaaa624f84e0e5acf659212a5c84c425a254447ad49304293071d3965f2741c0628bca37c740bfa3377649a431d372af54feaaa986041e1197e1cf4f432e657dd618ecbf5598aa89bab903b0b1d70a88f8c79a92865497690fcb8367a8a0075a732af3ecb677e772d856a34984bc2a1120fd296d35d6b156d2b141725eddeb9baa1858a48390c5d9f6818482497001530feaa80d0c897de63c81170202335afd78d6758ff088a86f3efb9213b4898ff832b58dbaa23b4e84b3bf79bc7078d7bc1a4a1d56b4494b97fc4febbd0e768ce2030ad9729cce74d8256bb90ab37588654815d9b1da978ce8e7f8cf8aaeb2768f5b")

	// Intial packet
	//p := quic.StrtoByte("c600000001045306bcce00405b4d980d67e740d1b668e76b52ca23f64addcda437e05054d512724a31b2f385a03e2dd0eff876df88c5c60c5d3d7315d9128b1c9df3e09494efb8956e6417966fd20d76d6a1e5589e423d4a91aed08131d1759881ef26ce26c84fe4447ae4ed10e4a317d9ec6d7f8810b54856d3a3fd89d6b1de7e6b71e1ad49f159f36ca17b8b598699cf0c66daf8cc0e97984d23779b4b348871a8b0525740878cc7074708bbbeecee8d465cdf220625b8349101f634c83bbce37f76ed614b645da8246592081a8812cf8659181e51e2eb06441245e048f239c853e882537509e687d44f4c71e05d24ed7df5cb3743825a2c4fb8fc3faedee1c97d0981e1d9a3d8e26c3732389e37132303557542459faa21da0abf37fd964e756a6016dcd45aa0dea0d69238699b50bbfe2304a3c3a4341d3eb61e2b9f7b1858ca4f084e13660a08a6932b2da6a07fb70eec2cc78946e7c2d0fc9aeb9db940cad6dbeefb5e0b0d9562db0539388982209f3a1024d51b3ecf86116fc98fe9d961f469984fe27be5c4528fe67e89645fca5a38c0de5399863bf26817486e128caae37a1878b7e643736b84de587174edfdd492fc98c00ba122be14fe927cdc923508c673f05c9f342f4249ae16172991bfec00e8abe7bc7c911314048ebc6198e22fa76dc204a29252bb95254169ca897ecd39403c185e1db3fc34be53ea01c0a3393562efcff2c542b4c73658b96de9dcdcd57b211dd137406d36692cb236091a6966a085228b378dc23589af9b2acee634e097cedf27ae9de0a2419ae41b690114273d71002331e327cc484e672109dad3e13002beac20b5efdc6134c4215483bbe81d1035fed9569b5f2aacfddec053fccf69a15b494bcf91bfeabb2d94958d94e80cd046be4c8674ea5661377b8b3098b8ae7cc4f831c9803b3a58118428e839b9dd572a40a18f61cdeee24375fedd6ac37f8769153cca42ed1382b0815e55cde56aa5777a7b217c3a6683c31e1767584b9bb3e438cbc0d11a8dbb9646f6c8ec01f019a180dcc96c61e23dd91c9258540e8e1446169019730a99147cc75cbaa69fe0b29ceb5d20542a838ea518325598245a317ddd41815303a2fb6641775d5d529e0850e9a3702a7c5fa1b3b21ad647eaa461a074ce9c656ace203495bd7a1081c156e8fdec69c75f728a5bacf1b9e2b1b9bfabab0fdbbc77de23222e46540dfc76f73d83c3cd79b1e52db15ddb50ca13bcea952bc8c8f54a99e85bb2dead548821bdf5e6a1825c4748326f5131dbddc17374a3cbd0f2c9a92ec4c7c41007d7618569fb5f707803488782fef4af45db976c5ec5b3aefa3d03c89cdee9712cb99286d6747cf00ac044e13e1a25e4ed0305340011d220f509d0a18d95ee5f9f03eac0a368cd5f595801789475c95a5f387b67572272de51cfb7eb924b90c27b33dac842627f97e3219b16393a00b08382db3fceb1cd3dfefe5c19b3624fe036931e3cb07bb86242e85fb34ae294a58a3975ec5109b460149dfc99df97f2da5bd223e55671855929292a47694566a25f659721972fc50641a40c974c17af4763d3283f27d6857fd1eed6ab123c8d69cdcafe6ac023c33f92e5043febcd9419ec6eb334a4122a48a85029fb8aff3eea2157ec10eeb79d2e312a274bafc13c6dd6a912307bd0f057a5ec5b6a27e047302abc7223dad017e422c9c8ee81154b2b8c6b3ed010ffa7a157663c5916394005f1924a9181f464b6ed0cfa772657fd72e856cb3b")

	// retry packet
	p := quic.StrtoByte("f00000000100045306bcce4d980d67e740d1b668e76b52ca23f64addcda437e05054d512724a31b2f385a03e2dd0eff876df88c5c60c5d3d7315d9128b1c9df3e09494efb8956e6417966fd20d76d6a1e5589e423d4a91aed08131d1759881ef26ce26c84fe417b8e7e5d4becff564572c6feae8351b")
	long, _ := quic.ParseLongHeaderPacket(p, quic.LongHeaderPacketTypeHandshake, true, 0)
	fmt.Printf("%+v\n", long)

}

func createshort() {
	var tlsinfo quic.TLSInfo
	// local-quic-nginx.pcapng
	chello := quic.StrtoByte("0100011d03030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000ce000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100005000302683300120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b740039004c46290b0d6a6b1948c8f8d73163a00504800800000604800800000704800800000404800c000008010009024064010480007530030245ac0b011a0c000e01040f08a6b98ba1886d7f23200100")
	serverHello := quic.StrtoByte("0200005603038c3e61f51d631ee58730c33b077bf4aafcf3613563be2658c4123b027c59be3600130100002e00330024001d0020a7c2f4e4183eac3fbd45014a123a2e66248f42317a4cc766bb093c39ab714442002b00020304")
	encryptedExtensions := quic.StrtoByte("08000077007500100005000302683300390068040480830000090103080240800504800100000604800100000704800100000104800124f803048000fff70e01020b01190a0103000a244ed270ddfc5efaba5e0f140000000000000001d02fd8a444709e6aa7123b4f0210c3dffe00bfbcf750cb56c5083f140009")
	serverCertificate := quic.StrtoByte("0b0004240000042000041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee0000")
	certificateVerify := quic.StrtoByte("0f00010408040100732245cc0e7bd5c6945fd99f827e847ded27a951141e290825a06418887fbcd30bf33f1b0c7dc742f8c816a0260b16f722bc6fa06cc466b9a86679f5a3d74ddaaeab80263ee0063bbe9bf8d3b81f051eb1c4bf917200d12a72ad99984d0d40660c04c2ac806ee95d5d42dd4544009e07a3025ea9ad74dbae9ec4541d041622a377be780959f8fc6b6ef79b8a81b85f07694d5e559f307599fbe335b852b663ff66b64b03c39f39bb873392ba6b4397ec517f5eaff9e5507c16283dfe3e8e020b3614092131cf5ab7e1fdf401bc36654e988c6684aa663191ab827e1a1d9aebb9481d509b8fdd9440b61c797473ccef765fd93382a4548194c0c739786b3a73ad")
	finishedMessage := quic.StrtoByte("140000206dda1413ecf0fea5af3f7415fd6c83c32cb487704fb8f99f19954e98709a7aa1")

	clientkey := quic.StrtoByte("0000000000000000000000000000000000000000000000000000000000000000")
	serverkey := quic.StrtoByte("a7c2f4e4183eac3fbd45014a123a2e66248f42317a4cc766bb093c39ab714442")

	commonkey, _ := curve25519.X25519(clientkey, serverkey)

	chello = append(chello, serverHello...)
	tlsinfo.KeyBlockTLS13 = quic.KeyscheduleToMasterSecret(commonkey, chello)

	chello = append(chello, encryptedExtensions...)
	chello = append(chello, serverCertificate...)
	chello = append(chello, certificateVerify...)
	chello = append(chello, finishedMessage...)
	tlsinfo.HandshakeMessages = chello
	tlsinfo = quic.KeyscheduleToAppTraffic(tlsinfo)

	stream := quic.NewControlStream()
	//stream := quic.StrtoByte("18010008f79865ef3351f87f3c43d689249f7fa7edc9b80684e3f08e")
	var short quic.ShortHeader

	tlsinfo.QPacketInfo.ShortHeaderPacketNumber = 1
	tlsinfo.QPacketInfo.ClientPacketNumberLength = 2
	tlsinfo.QPacketInfo.DestinationConnID = quic.StrtoByte("0000000000000001d02fd8a444709e6aa7123b4f")
	b := short.CreateShortHeaderPacket(tlsinfo, stream)

	fmt.Printf("create short header packet is %x\n", b)

}

//
//func _() {
//	var tlsinfo quic.TLSInfo
//	chello := quic.StrtoByte("0100013003030000000000000000000000000000000000000000000000000000000000000000000026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a130113021303010000e10000000e000c0000096c6f63616c686f7374000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100014001211717569632d6563686f2d6578616d706c6500120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b740039003e420b041fad788e0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00200100")
//	serverHello := quic.StrtoByte("020000560303000000000000000000000000000000000000000000000000000000000000000000130100002e002b0002030400330024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")
//	encryptedExtensions := quic.StrtoByte("08000090008e00100014001211717569632d6563686f2d6578616d706c650039007241ae0dff4c11f1b2cd93f99dc5cea1cc0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c0002101ae14003acb9d4c32fb8ab4ea68e7693000d7b268ba2b1ced2e48ed34a0a380e01040f044a4b30eb10045306bcce200100")
//	serverCertificate := quic.StrtoByte("0b0004240000042000041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee0000")
//	certificateVerify := quic.StrtoByte("0f00010408040100b9e4e4195c38fa814824567a0a3a5dbf667c93eb0ac0825d329d2bed57fa473817c47e811b3e803ba8020582ec67fe30d47f06b464e89684f064a0829272162cee7e2e2c692ffbade10bf8708ab6faf6bf5315ae2b200b9aac82d99e7e0dd473ee4ba2593490c4c27bc9caa9033e4e856018ab070d13d7eaca63c2b7a91a2f7d7ab2fef50d4d26fbc53d690c1fbc8ce8131215ccffba292cfcb4072f2a148ec036f0f72a32e16088543f3cb78d1b6762b270a6d23fbb30ca9f800d65f170e62b9cdc32ef1043557ab6ecaa1227478e3d1f7400d63f72f09171f68fb225f6951ca097dcb7e02b8b62e2b1b295bd25bbac7592460bb9fb2ad0a8b5d5f8c6af4bb5")
//	finishedMessage := quic.StrtoByte("14000020fa61ec0293c98834f638c818866a8582cb6e1683204bafe1e8f0b22ca2d49b0c")
//
//	clientkey := quic.StrtoByte("0000000000000000000000000000000000000000000000000000000000000000")
//	serverkey := quic.StrtoByte("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")
//
//	commonkey, _ := curve25519.X25519(clientkey, serverkey)
//
//	chello = append(chello, serverHello...)
//	tlsinfo.KeyBlockTLS13 = quic.KeyscheduleToMasterSecret(commonkey, chello)
//
//	chello = append(chello, encryptedExtensions...)
//	chello = append(chello, serverCertificate...)
//	chello = append(chello, certificateVerify...)
//	chello = append(chello, finishedMessage...)
//	tlsinfo.HandshakeMessages = chello
//	fmt.Printf("tls packet is %x\n", tlsinfo.HandshakeMessages)
//	tlsinfo = quic.KeyscheduleToAppTraffic(tlsinfo)
//
//	rawshort := quic.StrtoByte("5b1c83105391af6659528a0608870a0f71b8db45bf73fe653d0fa02f2cb1191f74891ad12255b75291c42f765b6c561c92af6f951ba68eaa0f7e5d74b5178636b1474c15a77bc254bb5123e06522f80a5ba611ab871bdaa6dc228d")
//	parsed := quic.ParseRawQuicPacket(rawshort, true, tlsinfo)
//	shortpacket := parsed[0].Packet.(quic.ShortHeader)
//	startPnumOffset := len(shortpacket.ToHeaderByte(shortpacket)) - 2
//
//	unpPacket := quic.UnprotectHeader(startPnumOffset, parsed[0].RawPacket, tlsinfo.KeyBlockTLS13.ServerAppHPKey, false, tlsinfo)
//	unpshort := unpPacket[0].Packet.(quic.ShortHeader)
//
//	keyblock := quic.QuicKeyBlock{
//		ServerKey: tlsinfo.KeyBlockTLS13.ServerAppKey,
//		ServerIV:  tlsinfo.KeyBlockTLS13.ServerAppIV,
//	}
//
//	plain := quic.DecryptQuicPayload(unpshort.PacketNumber, unpshort.ToHeaderByte(unpshort), unpshort.Payload, keyblock)
//	newconn := quic.ParseQuicFrame(plain, 0)
//	fmt.Printf("new connection id is %+v\n", newconn)
//
//	tlsinfo.QPacketInfo.InitialPacketNumber++
//
//	//var init quic.InitialPacket
//	//ack := init.CreateInitialAckPacket(quicinfo)
//	//fmt.Printf("ack packet is %x\n", ack)
//
//	fin := quic.CreateClientFinished(tlsinfo.HandshakeMessages, tlsinfo.KeyBlockTLS13.ClientFinishedKey)
//	fmt.Printf("finished crypto frame is %x\n", quic.ToPacket(fin))
//
//	var short quic.ShortHeader
//	payload := quic.StrtoByte("1900080068656c6c6f")
//	fmt.Printf("short header packet is %x\n", short.CreateShortHeaderPacket(tlsinfo, payload))
//
//}
