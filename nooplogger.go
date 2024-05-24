package aleo_oracle_sdk

import (
	"io"
	"log"
)

type noOpWriter struct {
	io.Writer
}

func (w *noOpWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

var noopLogger = log.New(new(noOpWriter), "", 0)
