package quic

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"reflect"
	"strconv"
)

type LocalIpMacAddr struct {
	LocalMacAddr []byte
	LocalIpAddr  []byte
	Index        int
}

func GetLocalIpAddr(ifname string) [4]byte {
	localif, err := getLocalIpAddr(ifname)
	if err != nil {
		log.Fatalf("Get local interface info is err : %v", err)
	}
	ipaddr := [4]byte{
		localif.LocalIpAddr[0],
		localif.LocalIpAddr[1],
		localif.LocalIpAddr[2],
		localif.LocalIpAddr[3],
	}
	return ipaddr
}

// ローカルのmacアドレスとIPを返す
func getLocalIpAddr(ifname string) (localif LocalIpMacAddr, err error) {
	nif, err := net.InterfaceByName(ifname)
	if err != nil {
		return localif, err
	}
	localif.LocalMacAddr = nif.HardwareAddr
	localif.Index = nif.Index

	addrs, err := nif.Addrs()
	if err != nil {
		return localif, err
	}
	for _, addr := range addrs {
		//if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				localif.LocalIpAddr = ipnet.IP.To4()
			}
		}
	}

	return localif, nil
}

func GetLocalInterface(ifname string) (localif LocalIpMacAddr, err error) {
	return getLocalIpAddr(ifname)
}

// https://www.ipa.go.jp/security/rfc/RFC5246-08JA.html
func randomByte(num int) []byte {
	b := make([]byte, num)
	rand.Read(b)
	return b
}

func RandomByte(num int) []byte {
	return randomByte(num)
}

func readByteNum(packet []byte, offset, n int64) []byte {
	r := bytes.NewReader(packet)
	sr := io.NewSectionReader(r, offset, n)

	buf := make([]byte, n)
	_, err := sr.Read(buf)
	if err != nil {
		log.Fatalf("read byte err : %v\n", err)
	}

	return buf
}

func noRandomByte(length int) []byte {
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = 0x00
	}
	return b
}

func getNonce(i, length int) []byte {
	b := make([]byte, length)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

// TLS1.3用
// https://tex2e.github.io/rfc-translater/html/rfc8446.html
// シーケンス番号とwrite_ivをxorした値がnonceになる
func getXORNonce(seqnum, writeiv []byte) []byte {
	nonce := make([]byte, len(writeiv))
	copy(nonce, writeiv)

	for i, b := range seqnum {
		nonce[4+i] ^= b
	}
	return nonce
}

func strtoByte(str string) []byte {
	b, _ := hex.DecodeString(str)
	return b
}

func StrtoByte(str string) []byte {
	return strtoByte(str)
}

func WriteHash(message []byte) []byte {
	hasher := sha256.New()
	hasher.Write(message)

	return hasher.Sum(nil)
}

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type ZeroSource struct{}

func (ZeroSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

func extendArrByZero(data []byte, to int) []byte {
	var extend []byte
	for i := 0; i < to-len(data); i++ {
		extend = append(extend, 0x00)
	}
	extend = append(extend, data...)
	return extend
}

func AddPaddingFrame(data []byte, to int) []byte {
	var extend []byte
	for i := 0; i <= to; i++ {
		extend = append(extend, 0x00)
	}
	//data = append(data, extend...)
	extend = append(extend, data...)
	return extend
}

func sum3BytetoLength(arr []byte) uint64 {
	length, _ := strconv.ParseUint(fmt.Sprintf("%x", arr), 16, 16)
	return length
}

func sumByteArr(arr []byte) uint {
	var sum uint
	for i := 0; i < len(arr); i++ {
		if i%2 == 0 {
			sum += uint(binary.BigEndian.Uint16(arr[i:]))
		}
	}
	//fmt.Printf("0x%x : %b\n", sum, sum)
	return sum
}

// 各構造体のフィールドが持つbyteをflatな配列にする
func toByteArr(value interface{}) []byte {
	rv := reflect.ValueOf(value)
	//rt := rv.Type()
	var arr []byte

	for i := 0; i < rv.NumField(); i++ {
		//field := rt.Field(i)
		//fmt.Printf("%s\n", field.Name)
		b := rv.Field(i).Interface().([]byte)
		arr = append(arr, b...)
	}

	return arr
}

func toByteLen(value interface{}) uint16 {
	rv := reflect.ValueOf(value)
	var arr []byte

	for i := 0; i < rv.NumField(); i++ {
		b := rv.Field(i).Interface().([]byte)
		arr = append(arr, b...)
	}

	return uint16(len(arr))
}

func UintTo2byte(data uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, data)
	return b
}

func UintTo3byte(data uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, data)
	return b[1:]
}

func UintTo4byte(data uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, data)
	return b
}

func ToPacket(value interface{}) []byte {
	return toByteArr(value)
}
