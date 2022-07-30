package quic

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"
	"log"
	"runtime"
)

func genrateClientECDHEKey() ECDHEKeys {
	// 秘密鍵となる32byteの乱数をセット
	//clientPrivateKey := randomByte(curve25519.ScalarSize)
	//clientPrivateKey := noRandomByte(32)
	clientPrivateKey := randomByte(32)

	// ClientKeyExchangeでサーバに送る公開鍵を生成
	clientPublicKey, _ := curve25519.X25519(clientPrivateKey, curve25519.Basepoint)

	return ECDHEKeys{
		PrivateKey: clientPrivateKey,
		PublicKey:  clientPublicKey,
	}
}

// golangのclientのをキャプチャしてそのままセットする
func setTLS13Extension(http2 bool) ([]byte, ECDHEKeys) {
	var tlsExtension []byte

	// set length
	if http2 {
		tlsExtension = append(tlsExtension, []byte{0x00, 0x78}...)
	} else {
		tlsExtension = append(tlsExtension, []byte{0x00, 0x6F}...)
	}

	//　status_reqeust
	tlsExtension = append(tlsExtension, []byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00}...)

	// supported_groups
	tlsExtension = append(tlsExtension, []byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d}...)

	// ec_point_formats
	tlsExtension = append(tlsExtension, []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}...)

	// signature_algorithms
	tlsExtension = append(tlsExtension, []byte{
		0x00, 0x0d, 0x00, 0x1a, 0x00, 0x18, 0x08, 0x04,
		0x04, 0x03, 0x08, 0x07, 0x08, 0x05, 0x08, 0x06,
		0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x05, 0x03,
		0x06, 0x03, 0x02, 0x01, 0x02, 0x03,
	}...)

	// renagotiation_info
	tlsExtension = append(tlsExtension, []byte{0xff, 0x01, 0x00, 0x01, 0x00}...)

	// Application Layer Protocol Negotiation
	if http2 {
		tlsExtension = append(tlsExtension, []byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32}...)
	}

	// signed_certificate_timestamp
	tlsExtension = append(tlsExtension, []byte{0x00, 0x12, 0x00, 0x00}...)
	// supported_versions
	tlsExtension = append(tlsExtension, []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}...)

	// 共通鍵を生成する
	clientkey := genrateClientECDHEKey()

	// key_share, DHEの公開鍵を送る
	tlsExtension = append(tlsExtension, []byte{0x00, 0x33, 0x00, 0x26, 0x00, 0x24}...)
	tlsExtension = append(tlsExtension, UintTo2byte(uint16(tls.X25519))...)

	// keyのLength = 32byte
	tlsExtension = append(tlsExtension, []byte{0x00, 0x20}...)
	// 公開鍵を追加
	tlsExtension = append(tlsExtension, clientkey.PublicKey...)

	return tlsExtension, clientkey
}

// https://pkg.go.dev/golang.org/x/crypto@v0.0.0-20220411220226-7b82a4e95df4/chacha20poly1305
func DecryptChacha20(message []byte, tlsinfo TLSInfo) []byte {
	header := message[0:5]
	chipertext := message[5:]
	var key, iv, nonce []byte

	if tlsinfo.State == ContentTypeHandShake {
		key = tlsinfo.KeyBlockTLS13.ServerHandshakeKey
		iv = tlsinfo.KeyBlockTLS13.ServerHandshakeIV
		nonce = getNonce(tlsinfo.ServerHandshakeSeq, 8)
	} else {
		key = tlsinfo.KeyBlockTLS13.ServerAppKey
		iv = tlsinfo.KeyBlockTLS13.ServerAppIV
		nonce = getNonce(tlsinfo.ServerAppSeq, 8)
	}

	//fmt.Printf("key is %x, iv is %x\n", key, iv)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}

	xornonce := getXORNonce(nonce, iv)

	//fmt.Printf("decrypt nonce is %x xornonce is %x, chipertext is %x, add is %x\n", nonce, xornonce, chipertext, header)
	plaintext, err := aead.Open(nil, xornonce, chipertext, header)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("plaintext is : %x\n", plaintext)
	return plaintext
}

func EncryptChacha20(message []byte, tlsinfo TLSInfo) []byte {
	var key, iv, nonce []byte

	// Finishedメッセージを送るとき
	if tlsinfo.State == ContentTypeHandShake {
		key = tlsinfo.KeyBlockTLS13.ClientHandshakeKey
		iv = tlsinfo.KeyBlockTLS13.ClientHandshakeIV
		nonce = getNonce(tlsinfo.ClientHandshakeSeq, 8)
	} else {
		// Application Dataを送る時
		key = tlsinfo.KeyBlockTLS13.ClientAppKey
		iv = tlsinfo.KeyBlockTLS13.ClientAppIV
		nonce = getNonce(tlsinfo.ClientAppSeq, 8)
	}

	fmt.Printf("key is %x, iv is %x\n", key, iv)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}
	// ivとnonceをxorのbit演算をする
	// 5.3. レコードごとのノンス
	// 2.埋め込まれたシーケンス番号は、静的なclient_write_ivまたはserver_write_iv（役割に応じて）とXORされます。
	xornonce := getXORNonce(nonce, iv)
	header := strtoByte("170303")
	// 平文→暗号化したときのOverHeadを足す
	totalLength := len(message) + 16

	header = append(header, UintTo2byte(uint16(totalLength))...)

	fmt.Printf("encrypt now nonce is %x xornonce is %x, plaintext is %x, add is %x\n", nonce, xornonce, message, header)
	ciphertext := aead.Seal(header, xornonce, message, header)

	return ciphertext
}

// HKDF-Extractは、上部からSalt引数を、左側からIKM引数を取り
func hkdfExtract(secret, salt []byte) []byte {
	hash := sha256.New
	return hkdf.Extract(hash, secret, salt)
}

func hkdfExpand(secret, hkdflabel []byte, length int) []byte {
	hash := sha256.New
	expand := hkdf.Expand(hash, secret, hkdflabel)
	b := make([]byte, length)
	io.ReadFull(expand, b)

	return b
}

func hkdfExpandLabel(secret, label, ctx []byte, length int) []byte {
	// labelを作成
	tlslabel := []byte(`tls13 `)
	tlslabel = append(tlslabel, label...)

	// lengthをセット
	hkdflabel := UintTo2byte(uint16(length))
	hkdflabel = append(hkdflabel, byte(len(tlslabel)))
	hkdflabel = append(hkdflabel, tlslabel...)

	hkdflabel = append(hkdflabel, byte(len(ctx)))
	hkdflabel = append(hkdflabel, ctx...)

	return hkdfExpand(secret, hkdflabel, length)
}

func deriveSecret(secret, label, messages_byte []byte) []byte {
	return hkdfExpandLabel(secret, label, messages_byte, 32)
}

func KeyscheduleToMasterSecret(sharedkey, handshake_messages []byte) KeyBlockTLS13 {

	// 32byteの0
	zero := noRandomByte(32)
	zerohash := WriteHash(nil)
	// 0からearly secretを作成する
	earlySecret := hkdfExtract(zero, zero)

	// {client} derive secret for handshake "tls13 derived"
	derivedSecretForhs := deriveSecret(earlySecret, DerivedLabel, zerohash)
	fmt.Printf("derivedSecretForhs %x\n", derivedSecretForhs)

	// {client} extract secret "handshake":
	handshake_secret := hkdfExtract(sharedkey, derivedSecretForhs)
	fmt.Printf("handshake_secret is : %x\n", handshake_secret)

	hash_messages := WriteHash(handshake_messages)
	fmt.Printf("hashed messages is %x\n", hash_messages)

	// {client} derive secret "tls13 c hs traffic":
	chstraffic := deriveSecret(handshake_secret, ClienthsTraffic, hash_messages)
	fmt.Printf("CLIENT_HANDSHAKE_TRAFFIC_SECRET %x %x\n", zero, chstraffic)

	// Finished message用のキー
	clientfinkey := deriveSecret(chstraffic, FinishedLabel, nil)
	//fmt.Printf("clientfinkey is : %x\n", clientfinkey)

	// {client} derive secret "tls13 s hs traffic":
	shstraffic := deriveSecret(handshake_secret, ServerhsTraffic, hash_messages)
	fmt.Printf("SERVER_HANDSHAKE_TRAFFIC_SECRET %x %x\n", zero, shstraffic)

	// Finished message用のキー
	serverfinkey := deriveSecret(shstraffic, FinishedLabel, nil)
	fmt.Printf("serverfinkey is : %x\n", serverfinkey)

	derivedSecretFormaster := deriveSecret(handshake_secret, DerivedLabel, zerohash)
	fmt.Printf("derivedSecretFormaster is : %x\n", derivedSecretFormaster)

	extractSecretMaster := hkdfExtract(zero, derivedSecretFormaster)
	fmt.Printf("extractSecretMaster is : %x\n", extractSecretMaster)

	// {client} derive write traffic keys for handshake data from server hs traffic:
	// 7.3. トラフィックキーの計算
	clienttraffickey := hkdfExpandLabel(chstraffic, quicKeyLabel, nil, 16)
	fmt.Printf("client traffic key is : %x\n", clienttraffickey)

	clienttrafficHPkey := hkdfExpandLabel(chstraffic, quicHPLabel, nil, 16)
	fmt.Printf("client traffic HP key is : %x\n", clienttrafficHPkey)

	clienttrafficiv := hkdfExpandLabel(chstraffic, quicIVLabel, nil, 12)
	fmt.Printf("client traffic iv is : %x\n", clienttrafficiv)

	servertraffickey := hkdfExpandLabel(shstraffic, quicKeyLabel, nil, 16)
	fmt.Printf("server traffic key is : %x\n", servertraffickey)

	servertrafficHPkey := hkdfExpandLabel(shstraffic, quicHPLabel, nil, 16)
	fmt.Printf("server traffic hp key is : %x\n", servertrafficHPkey)

	servertrafficiv := hkdfExpandLabel(shstraffic, quicIVLabel, nil, 12)
	fmt.Printf("server traffic iv is : %x\n", servertrafficiv)

	return KeyBlockTLS13{
		HandshakeSecret:       handshake_secret,
		ClientHandshakeSecret: chstraffic,
		ClientHandshakeKey:    clienttraffickey,
		ClientHandshakeHPKey:  clienttrafficHPkey,
		ClientHandshakeIV:     clienttrafficiv,
		ClientFinishedKey:     clientfinkey,
		ServerHandshakeSecret: shstraffic,
		ServerHandshakeKey:    servertraffickey,
		ServerHandshakeHPKey:  servertrafficHPkey,
		ServerHandshakeIV:     servertrafficiv,
		ServerFinishedKey:     serverfinkey,
		MasterSecret:          extractSecretMaster,
	}
}

func KeyscheduleToAppTraffic(tlsinfo TLSInfo) TLSInfo {
	hash_messages := WriteHash(tlsinfo.Handshakemessages)
	fmt.Printf("hashed messages is %x\n", hash_messages)

	zero := noRandomByte(32)

	// {client} derive secret "tls13 c ap traffic":
	captraffic := deriveSecret(tlsinfo.KeyBlockTLS13.MasterSecret, ClientapTraffic, hash_messages)
	fmt.Printf("CLIENT_TRAFFIC_SECRET_0 %x %x\n", zero, captraffic)
	saptraffic := deriveSecret(tlsinfo.KeyBlockTLS13.MasterSecret, ServerapTraffic, hash_messages)
	fmt.Printf("SERVER_TRAFFIC_SECRET_0 %x %x\n", zero, saptraffic)

	// 7.3. トラフィックキーの計算, Application用
	tlsinfo.KeyBlockTLS13.ClientAppKey = hkdfExpandLabel(captraffic, []byte(`key`), nil, 32)
	tlsinfo.KeyBlockTLS13.ClientAppIV = hkdfExpandLabel(captraffic, []byte(`iv`), nil, 12)
	fmt.Printf("clientAppKey and IV is : %x, %x\n", tlsinfo.KeyBlockTLS13.ClientAppKey, tlsinfo.KeyBlockTLS13.ClientAppIV)

	tlsinfo.KeyBlockTLS13.ServerAppKey = hkdfExpandLabel(saptraffic, []byte(`key`), nil, 32)
	tlsinfo.KeyBlockTLS13.ServerAppIV = hkdfExpandLabel(saptraffic, []byte(`iv`), nil, 12)
	fmt.Printf("serverAppkey and IV is : %x, %x\n", tlsinfo.KeyBlockTLS13.ServerAppKey, tlsinfo.KeyBlockTLS13.ServerAppIV)

	return tlsinfo
}

// 4.4.3. Certificate Verify
func VerifyServerCertificate(pubkey *rsa.PublicKey, signature, handshake_messages []byte) {
	hash_messages := WriteHash(handshake_messages)

	hasher := sha256.New()
	// 64回繰り返されるオクテット32（0x20）で構成される文字列
	hasher.Write(strtoByte(str0x20x64))
	// コンテキスト文字列 = "TLS 1.3, server CertificateVerify"
	hasher.Write(serverCertificateContextString)
	// セパレータとして機能する単一の0バイト
	hasher.Write([]byte{0x00})
	hasher.Write(hash_messages)
	signed := hasher.Sum(nil)
	fmt.Printf("hash_messages is %x, signed is %x\n", hash_messages, signed)

	signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	err := rsa.VerifyPSS(pubkey, crypto.SHA256, signed, signature, signOpts)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Server Certificate Verify is OK !!")
}

func readCertificates(packet []byte) []*x509.Certificate {

	var b []byte
	var certificates []*x509.Certificate

	//　https://pkg.go.dev/crypto/x509#SystemCertPool
	// OSにインストールされている証明書を読み込む
	var ospool *x509.CertPool
	var err error
	if runtime.GOOS != "windows" {
		ospool, err = x509.SystemCertPool()
		if err != nil {
			log.Fatalf("get SystemCertPool err : %v\n", err)
		}
	} else {
		ospool = x509.NewCertPool()
	}

	// TLS Handshak protocolのCertificatesのLengthが0になるまでx509証明書をReadする
	// 読み込んだx509証明書を配列に入れる
	length := sum3BytetoLength(packet[0:3])
	b = packet[3 : length+3]
	//fmt.Printf("%x\n", b)
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		log.Fatalf("ParseCertificate error : %s", err)
	}
	certificates = append(certificates, cert)
	//for {
	//	if len(packet) == 0 {
	//		break
	//	} else {
	//		length := sum3BytetoLength(packet[0:3])
	//		//b := make([]byte, length)
	//		//b = readByteNum(packet, 3, int64(length))
	//		b = packet[3 : length+3]
	//		fmt.Printf("%x\n", b)
	//		cert, err := x509.ParseCertificate(b)
	//		if err != nil {
	//			log.Fatalf("ParseCertificate error : %s", err)
	//		}
	//		certificates = append(certificates, cert)
	//		//byte配列を縮める
	//		packet = packet[3+length:]
	//	}
	//}

	// 証明書を検証する
	// 配列にはサーバ証明書、中間証明書の順番で格納されているので中間証明書から検証していくので
	// forloopをdecrementで回す
	for i := len(certificates) - 1; i >= 0; i-- {
		var opts x509.VerifyOptions
		if len(certificates[i].DNSNames) == 0 {
			opts = x509.VerifyOptions{
				Roots: ospool,
			}
		} else {
			opts = x509.VerifyOptions{
				DNSName: certificates[i].DNSNames[0],
				Roots:   ospool,
			}
		}

		// 検証
		_, err = certificates[i].Verify(opts)
		if err != nil {
			log.Fatalf("failed to verify certificate : %v\n", err)
		}
		if 0 < i {
			ospool.AddCert(certificates[1])
		}
	}
	fmt.Println("証明書マジ正しい！")
	return certificates
}
