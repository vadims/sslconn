package sslconn

import (
	"io"
)

func writeBytesTo(bytes []byte, writer io.Writer) error {
	for len(bytes) > 0 {
		wrote, err := writer.Write(bytes)
		if err != nil {
			return err
		}
		bytes = bytes[wrote:]
	}
	return nil
}
