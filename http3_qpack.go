package quic

import (
	"fmt"
	"strconv"
	"strings"
)

type Http3Header struct {
	Name  string
	Value string
}

var Http3StaticTable = []Http3Header{
	{Name: ":authority"},
	{Name: ":path", Value: "/"},
	{Name: "age", Value: "0"},
	{Name: "content-disposition"},
	{Name: "content-length", Value: "0"},
	{Name: "cookie"},
	{Name: "date"},
	{Name: "etag"},
	{Name: "if-modified-since"},
	{Name: "if-none-match"},
	{Name: "last-modified"},
	{Name: "link"},
	{Name: "location"},
	{Name: "referer"},
	{Name: "set-cookie"},
	{Name: ":method", Value: "CONNECT"},
	{Name: ":method", Value: "DELETE"},
	{Name: ":method", Value: "GET"},
	{Name: ":method", Value: "HEAD"},
	{Name: ":method", Value: "OPTIONS"},
	{Name: ":method", Value: "POST"},
	{Name: ":method", Value: "PUT"},
	{Name: ":scheme", Value: "http"},
	{Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "103"},
	{Name: ":status", Value: "200"},
	{Name: ":status", Value: "304"},
	{Name: ":status", Value: "404"},
	{Name: ":status", Value: "503"},
	{Name: "accept", Value: "*/*"},
	{Name: "accept", Value: "application/dns-message"},
	{Name: "accept-encoding", Value: "gzip, deflate, br"},
	{Name: "accept-ranges", Value: "bytes"},
	{Name: "access-control-allow-headers", Value: "cache-control"},
	{Name: "access-control-allow-headers", Value: "content-type"},
	{Name: "access-control-allow-origin", Value: "*"},
	{Name: "cache-control", Value: "max-age=0"},
	{Name: "cache-control", Value: "max-age=2592000"},
	{Name: "cache-control", Value: "max-age=604800"},
	{Name: "cache-control", Value: "no-cache"},
	{Name: "cache-control", Value: "no-store"},
	{Name: "cache-control", Value: "public,max-age=31536000"},
	{Name: "content-encoding", Value: "br"},
	{Name: "content-encoding", Value: "gzip"},
	{Name: "content-type", Value: "application/dns-message"},
	{Name: "content-type", Value: "application/javascript"},
	{Name: "content-type", Value: "application/json"},
	{Name: "content-type", Value: "application/x-www-form-urlencoded"},
	{Name: "content-type", Value: "image/gif"},
	{Name: "content-type", Value: "image/jpeg"},
	{Name: "content-type", Value: "image/png"},
	{Name: "content-type", Value: "text/css"},
	{Name: "content-type", Value: "text/html; charset=utf-8"},
	{Name: "content-type", Value: "text/plain"},
	{Name: "content-type", Value: "text/plain;charset=utf-8"},
	{Name: "range", Value: "bytes=0-"},
	{Name: "strict-transport-security", Value: "max-age=31536000"},
	{Name: "strict-transport-security", Value: "max-age=31536000; includesubdomains"},
	{Name: "strict-transport-security", Value: "max-age=31536000; includesubdomains; preload"},
	{Name: "vary", Value: "accept-encoding"},
	{Name: "vary", Value: "origin"},
	{Name: "x-content-type-options", Value: "nosniff"},
	{Name: "x-xss-protection", Value: "1; mode=block"},
	{Name: ":status", Value: "100"},
	{Name: ":status", Value: "204"},
	{Name: ":status", Value: "206"},
	{Name: ":status", Value: "302"},
	{Name: ":status", Value: "400"},
	{Name: ":status", Value: "403"},
	{Name: ":status", Value: "421"},
	{Name: ":status", Value: "425"},
	{Name: ":status", Value: "500"},
	{Name: "accept-language"},
	{Name: "access-control-allow-credentials", Value: "FALSE"},
	{Name: "access-control-allow-credentials", Value: "TRUE"},
	{Name: "access-control-allow-headers", Value: "*"},
	{Name: "access-control-allow-methods", Value: "get"},
	{Name: "access-control-allow-methods", Value: "get, post, options"},
	{Name: "access-control-allow-methods", Value: "options"},
	{Name: "access-control-expose-headers", Value: "content-length"},
	{Name: "access-control-request-headers", Value: "content-type"},
	{Name: "access-control-request-method", Value: "get"},
	{Name: "access-control-request-method", Value: "post"},
	{Name: "alt-svc", Value: "clear"},
	{Name: "authorization"},
	{Name: "content-security-policy", Value: "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{Name: "early-data", Value: "1"},
	{Name: "expect-ct"},
	{Name: "forwarded"},
	{Name: "if-range"},
	{Name: "origin"},
	{Name: "purpose", Value: "prefetch"},
	{Name: "server"},
	{Name: "timing-allow-origin", Value: "*"},
	{Name: "upgrade-insecure-requests", Value: "1"},
	{Name: "user-agent"},
	{Name: "x-forwarded-for"},
	{Name: "x-frame-options", Value: "deny"},
	{Name: "x-frame-options", Value: "sameorigin"},
}

func DecodeHttp3Header(headerByte []byte) []Http3Header {

	var http3Header []Http3Header

	for i := 0; i < len(headerByte); i++ {
		binstr := fmt.Sprintf("%08b", headerByte[i])
		if strings.HasPrefix(binstr, "1") {
			fmt.Printf("i is %d, byte is %x, binstr is %s\n", i, headerByte[i], binstr)
			// インデックスヘッダフィールド表現(1で始まる)
			// 残り7bitを10進数にする
			d, _ := strconv.ParseInt(binstr[1:], 2, 8)
			http3Header = append(http3Header, Http3StaticTable[d-1])
		} else if strings.HasPrefix(binstr, "01") {
			fmt.Printf("i is %d, byte is %x, binstr is %s\n", i, headerByte[i], binstr)
			var header Http3Header
			// インデックス更新を伴うリテラルヘッダフィールド（01で始まる）
			// Httpヘッダ名をIndex番号で取得
			d, _ := strconv.ParseInt(binstr[2:], 2, 8)
			header.Name = Http3StaticTable[d-1].Name

			//　Valueの値を2進数にする
			binstr = fmt.Sprintf("%08b", headerByte[i+1])
			if binstr[0:1] == "1" {
				d, _ := strconv.ParseInt(binstr[1:], 2, 8)
				header.Value = HuffmanDecode(headerByte[i+2 : i+2+int(d)])
				http3Header = append(http3Header, header)
				// 次のヘッダが始まる位置にiを進めるためにインクリメント
				i = i + 1 + int(d)
			}
		} else if binstr == "00000000" {

			binstr = fmt.Sprintf("%08b", headerByte[i+1])
			if binstr[0:1] == "1" {
				// Name Stringを処理する
				d, _ := strconv.ParseInt(binstr[1:], 2, 8)
				nameString := HuffmanDecode(headerByte[i+2 : i+2+int(d)])
				// Name Valueを処理する
				i = i + 2 + int(d)
				binstr = fmt.Sprintf("%08b", headerByte[i])
				d, _ = strconv.ParseInt(binstr[1:], 2, 8)
				nameValue := HuffmanDecode(headerByte[i+1 : i+1+int(d)])

				// 次のヘッダが始まる位置にiを進めるためにインクリメント
				i += int(d)

				http3Header = append(http3Header, Http3Header{
					Name:  nameString,
					Value: nameValue,
				})

			}
		}
	}

	return http3Header
}

func getHttp3HeaderIndexByNameAndValue(name, value string) (index int, staticval bool) {
	for k, v := range Http3StaticTable {
		if v.Name == name && v.Value == value {
			index = k
			staticval = true
			break
		} else if v.Name == name && v.Value != value {
			index = k
			staticval = false
		}
	}
	return index, staticval
}

func NewHttp3Header(name, value string) (headerByte []byte) {

	index, staticval := getHttp3HeaderIndexByNameAndValue(name, value)
	if !staticval {
		/*
			0   1   2   3   4   5   6   7
			+---+---+---+---+---+---+---+---+
			| 0 | 1 | N | T |Name Index (4+)|
			+---+---+---+---+---------------+
			| H |     Value Length (7+)     |
			+---+---------------------------+
			|  Value String (Length bytes)  |
			+-------------------------------+
		*/
		var headerIndex uint64
		// 15以下なら
		if index <= 15 {
			// Name Indexの前の先頭4bitは0101で固定
			headerIndex, _ = strconv.ParseUint(fmt.Sprintf("0101%04b", index), 2, 8)
			headerByte = append(headerByte, byte(headerIndex))
		} else {
			// Name Indexの前の先頭4bitは0101で固定
			headerIndex, _ = strconv.ParseUint(fmt.Sprintf("0101%04b", 15), 2, 8)
			index -= 15
			headerByte = append(headerByte, byte(headerIndex))
			headerIndex, _ = strconv.ParseUint(fmt.Sprintf("%08b", index), 2, 8)
			headerByte = append(headerByte, byte(headerIndex))
		}

		// 文字列をHuffuman Encodeする
		encodeVal := HuffmanEncode(value)
		headerVal, _ := strconv.ParseUint(fmt.Sprintf("1%07b", len(encodeVal)), 2, 8)

		headerByte = append(headerByte, byte(headerVal))
		headerByte = append(headerByte, encodeVal...)
	} else {
		/*
		     0   1   2   3   4   5   6   7
		   +---+---+---+---+---+---+---+---+
		   | 1 | T |      Index (6+)       |
		   +---+---+-----------------------+
		*/
		headerVal, _ := strconv.ParseUint(fmt.Sprintf("11%06b", index), 2, 8)
		headerByte = append(headerByte, byte(headerVal))
	}

	fmt.Printf("Name is %s, Values is %s, byte is %x\n", name, value, headerByte)
	return headerByte
}
