package sslconn

/*
#cgo pkg-config: openssl
#include "cgo_binding.h"
*/
import "C"
import (
	"errors"
	"io/ioutil"
	"reflect"
	"unsafe"
)

type Cert struct {
	cert *C.X509
}

func NewCert(filename string) (*Cert, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var sslConnError C.SSLConnError
	header := (*reflect.SliceHeader)((unsafe.Pointer(&contents)))
	cert := C.SSLConn_X509_new(unsafe.Pointer(header.Data), C.int(header.Len),
		(*C.SSLConnError)(unsafe.Pointer(&sslConnError)))
	if cert == nil {
		return nil, errors.New(C.GoString(&sslConnError.string[0]))
	}
	return &Cert{cert}, nil
}

func (c *Cert) Free() {
	if c.cert != nil {
		C.X509_free(c.cert)
		c.cert = nil
	}
}
