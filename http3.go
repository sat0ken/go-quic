package quic

const (
	HTTP3TypeData = iota
	HTTP3TypeHeader
)

type HTTP3Frame struct {
	Type    []byte
	Length  []byte
	Payload []byte
}

func NewControlStream() (data []byte) {
	// Stream Type : Control Stream
	data = []byte{0x00}
	// Type : Settings
	data = append(data, 0x04)
	// set Length
	data = append(data, 0x00)

	// Stream Frame にセット
	stream := StreamFrame{
		Type:       []byte{0x08},
		StreamID:   []byte{0x02},
		StreamData: data,
	}

	return toByteArr(stream)
}

func NewHttp3Request() (data []byte) {
	// Stream Type : Control Stream
	//header := strtoByte("0000508b089d5c0b8170dc081a699fd1c1d75f10839bd9ab5f508bed6988b4c7531efdfad867")
	header := CreateHTTP3HeaderByteArray()
	// Type : Header
	data = append(data, 0x01)
	// set Length
	data = append(data, byte(len(header)))
	// set header data
	data = append(data, header...)

	// Stream Frame にセット
	// 最下位BitのFINビット=1で送るのでTypeは9
	stream := StreamFrame{
		Type:       []byte{0x09},
		StreamID:   []byte{0x00},
		StreamData: data,
	}

	return toByteArr(stream)
}

func ParseHTTP3(packet []byte) (h3frame []HTTP3Frame) {
	for i := 0; i < len(packet); i++ {
		switch packet[0] {
		case HTTP3TypeHeader:
			frame := HTTP3Frame{
				Type:   packet[0:1],
				Length: packet[1:2],
			}
			frame.Payload = packet[2 : 2+int(frame.Length[0])]
			h3frame = append(h3frame, frame)

			// 次のフレームを読み込む
			packet = packet[2+int(frame.Length[0]):]
			i = 0
		case HTTP3TypeData:
			frame := HTTP3Frame{
				Type:   packet[0:1],
				Length: packet[1:2],
			}
			frame.Payload = packet[2 : 2+int(frame.Length[0])]
			h3frame = append(h3frame, frame)
			// 次のフレームを読み込む
			packet = packet[2+int(frame.Length[0]):]
			i = 0
		}
	}
	return h3frame
}

func CreateHTTP3HeaderByteArray() []byte {
	header := []byte{0x00, 0x00}

	header = append(header, NewHttp3Header(":authority", "127.0.0.1:18443")...)
	header = append(header, NewHttp3Header(":method", "GET")...)
	header = append(header, NewHttp3Header(":path", "/")...)
	header = append(header, NewHttp3Header(":scheme", "https")...)
	header = append(header, NewHttp3Header("accept-encoding", "gzip")...)
	header = append(header, NewHttp3Header("user-agent", "quic-go HTTP/3")...)

	return header
}
