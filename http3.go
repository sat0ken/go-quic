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
