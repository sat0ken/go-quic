package quic

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
	header := strtoByte("0000508b089d5c0b8170dc081a699fd1c1d75f10839bd9ab5f508bed6988b4c7531efdfad867")
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
