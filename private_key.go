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

type PrivateKey struct {
	key *C.EVP_PKEY
}

func NewPrivateKey(filename string) (*PrivateKey, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var sslConnError C.SSLConnError
	header := (*reflect.SliceHeader)((unsafe.Pointer(&contents)))
	key := C.SSLConn_EVP_PKEY_new(unsafe.Pointer(header.Data), C.int(header.Len),
		(*C.SSLConnError)(unsafe.Pointer(&sslConnError)))
	if key == nil {
		return nil, errors.New(C.GoString(&sslConnError.string[0]))
	}
	return &PrivateKey{key}, nil
}

func (k *PrivateKey) Free() {
	if k.key != nil {
		C.EVP_PKEY_free(k.key)
		k.key = nil
	}
}
