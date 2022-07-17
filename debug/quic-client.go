package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/logging"
	"io"
	"log"
	"os"
)

type zeroSource2 struct{}

func (zeroSource2) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

func main() {
	w := os.Stdout
	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Rand:         zeroSource2{},
		NextProtos:   []string{"quic-echo-example"},
		KeyLogWriter: w,
	}

	quicconfig := &quic.Config{
		Tracer: logging.NewMultiplexedTracer(),
	}

	conn, err := quic.DialAddr("localhost:18443", tlsConf, quicconfig)
	if err != nil {
		log.Fatal(err)
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	message := []byte(`hello`)

	stream.Write(message)

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Message from server : %s\n", string(buf))
}
