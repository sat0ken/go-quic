package main

import (
	"context"
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"io"
	"log"
	"os"
)

const addr = "localhost:18443"

type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

type loggingWriter struct{ io.Writer }

// https://github.com/lucas-clemente/quic-go/blob/master/example/echo/echo.go
func main() {
	w := os.Stdout

	tlsCert, err := tls.LoadX509KeyPair("./my-tls.pem", "./my-tls-key.pem")
	if err != nil {
		log.Fatalf("Load key pair is err %v\n", err)
	}

	listener, err := quic.ListenAddr(addr, &tls.Config{
		Rand:         zeroSource{},
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"quic-echo-example"},
		KeyLogWriter: w,
	}, nil)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := listener.Accept(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	io.Copy(loggingWriter{stream}, stream)

}

func (w loggingWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}
