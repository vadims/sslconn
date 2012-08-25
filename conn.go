// Package sslconn provides a CGO wrapper around a tiny subset of the OpenSSL
// API to enable OpenSSL connections on top of io.Reader/io.Writer.
package sslconn

/*
#cgo pkg-config: openssl
#include "cgo_binding.h"
*/
import "C"
import (
	"errors"
	"io"
	"reflect"
	"sync"
	"unsafe"
)

var (
	ErrAgain  = errors.New("EAGAIN")
	ErrClosed = errors.New("CLOSED")
	ErrIO     = errors.New("IO")
)

type VerifyMode int

const (
	VERIFY_NONE = iota
	VERIFY_PEER
	VERIFY_FAIL_IF_NO_PEER_CERT
	VERIFY_CLIENT_ONCE
)

type Config struct {
	PrivateKey       *PrivateKey
	Cert             *Cert
	Verify           VerifyMode
	CipherList       string
	SessionIdContext string
	SessionCacheSize int
}

type Conn struct {
	sslConn *C.SSLConn
	lock    *sync.Mutex
	reader  *NonBlockingReader
	writer  *NonBlockingWriter
}

const (
	defaultBufferSize = 32 * 1024
)

// Initialize OpenSSL
func init() {
	C.SSLConn_init()
}

// Creates new SSL connection for the underlying reader and writer. 
func NewConn(reader io.Reader, writer io.Writer,
	config *Config, server bool) (*Conn, error) {
	c := &Conn{}

	if server && (config.Cert == nil || config.PrivateKey == nil) {
		panic("Cert and PrivateKey are required for server SSL connections")
	}

	sslConnConfig := newSSLConnConfig(config)
	defer cleanupSSLConnConfig(sslConnConfig)
	sslConnConfig.is_server = C.bool(server)
	sslConnConfig.ptr = unsafe.Pointer(c)

	var sslConnError C.SSLConnError
	c.sslConn = C.SSLConn_new(sslConnConfig,
		(*C.SSLConnError)(unsafe.Pointer(&sslConnError)))
	if c.sslConn == nil {
		return nil, errors.New(C.GoString(&sslConnError.string[0]))
	}

	c.lock = &sync.Mutex{}
	c.reader = NewNonBlockingReader(reader, defaultBufferSize)
	c.writer = NewNonBlockingWriter(writer, defaultBufferSize)
	return c, nil
}

// Initiates the SSL handshake, must be called once before read or write.
func (c *Conn) Handshake() error {
	_, err := c.retCodeHandler(func(e *C.SSLConnError) C.int {
		return C.SSLConn_do_handshake(c.sslConn,
			(*C.SSLConnError)(unsafe.Pointer(e)))
	})
	return err
}

func (c *Conn) Read(b []byte) (int, error) {
	c.reader.WaitUntilReady()

	return c.retCodeHandler(func(e *C.SSLConnError) C.int {
		header := (*reflect.SliceHeader)((unsafe.Pointer(&b)))
		return C.SSLConn_read(c.sslConn, unsafe.Pointer(header.Data),
			C.int(header.Len), (*C.SSLConnError)(unsafe.Pointer(e)))
	})
}

func (c *Conn) Write(b []byte) (int, error) {
	c.writer.WaitUntilReady()

	return c.retCodeHandler(func(e *C.SSLConnError) C.int {
		header := (*reflect.SliceHeader)((unsafe.Pointer(&b)))
		return C.SSLConn_write(c.sslConn, unsafe.Pointer(header.Data),
			C.int(header.Len), (*C.SSLConnError)(unsafe.Pointer(e)))
	})
}

// Perform a clean shutdown of the SSL connection. This does not close
// the underlying reader or writer.
func (c *Conn) Shutdown() error {
	_, err := c.retCodeHandler(func(e *C.SSLConnError) C.int {
		return C.SSLConn_shutdown(c.sslConn,
			(*C.SSLConnError)(unsafe.Pointer(e)))
	})
	return err
}

// Frees any CGO resources, after Free is called the connection is no longer
// usable.
func (c *Conn) Free() {
	C.SSLConn_free(c.sslConn)
	c.sslConn = nil
	c.reader.Close()
	c.writer.Close()
}

// Helper for functions that use SSL_get_error
func (c *Conn) retCodeHandler(fn func(*C.SSLConnError) C.int) (int, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	var err C.SSLConnError
	for {
		code := fn(&err)
		if code > 0 {
			return int(code), nil
		}

		switch code {
		case C.SSLConn_WANT_READ:
			c.reader.WaitUntilReady()
		case C.SSLConn_WANT_WRITE:
			c.writer.WaitUntilReady()
		case C.SSLConn_ZERO_RETURN:
			return 0, io.EOF
		case C.SSLConn_SYSCALL:
			return 0, ErrIO
		default:
			return 0, errors.New(C.GoString(&err.string[0]))
		}
	}
	panic("Should have had an error")
}

func newSSLConnConfig(config *Config) *C.SSLConnConfig {
	c := &C.SSLConnConfig{}
	// TODO: make configurable
	c.options = C.SSL_OP_NO_SSLv2 | C.SSL_OP_NO_SSLv3

	if config.PrivateKey != nil {
		c.private_key = config.PrivateKey.key
	}

	if config.Cert != nil {
		c.cert = config.Cert.cert
	}

	switch config.Verify {
	case VERIFY_NONE:
		c.verify_mode = C.SSL_VERIFY_NONE
	case VERIFY_PEER:
		c.verify_mode = C.SSL_VERIFY_PEER
	case VERIFY_CLIENT_ONCE:
		c.verify_mode = C.SSL_VERIFY_CLIENT_ONCE
	case VERIFY_FAIL_IF_NO_PEER_CERT:
		c.verify_mode = C.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	}

	if len(config.CipherList) > 0 {
		c.cipher_list = C.CString(config.CipherList)
	} else {
		c.cipher_list = nil
	}

	c.sess_cache_size = C.long(config.SessionCacheSize)

	if len(config.SessionIdContext) > 0 {
		c.session_id_context = C.CString(config.SessionIdContext)
	} else {
		c.session_id_context = nil
	}

	return c
}

func cleanupSSLConnConfig(config *C.SSLConnConfig) {
	if config.cipher_list != nil {
		C.free(unsafe.Pointer(config.cipher_list))
	}

	if config.session_id_context != nil {
		C.free(unsafe.Pointer(config.session_id_context))
	}
}

//export goconn_bio_read
func goconn_bio_read(bio *C.BIO, buffer *C.char, length int) (read int, errcode int) {
	conn := (*Conn)(bio.ptr)
	read, err := conn.reader.Read(goSliceNoCopy(buffer, length))

	switch err {
	case nil:
		return read, 0
	case io.EOF:
		return 0, 0
	case ErrAgain:
		return -1, int(C.SSLConn_EAGAIN)
	}
	return -1, int(C.SSLConn_EIO)
}

//export goconn_bio_write
func goconn_bio_write(bio *C.BIO, buffer *C.char, length int) (int, int) {
	conn := (*Conn)(bio.ptr)
	wrote, err := conn.writer.Write(goSliceNoCopy(buffer, length))

	switch err {
	case nil:
		return wrote, 0
	case ErrAgain:
		return -1, int(C.SSLConn_EAGAIN)
	}

	return -1, int(C.SSLConn_EIO)
}

func goSliceNoCopy(buffer *C.char, length int) []byte {
	var slice []byte
	header := (*reflect.SliceHeader)((unsafe.Pointer(&slice)))
	header.Cap = length
	header.Len = length
	header.Data = uintptr(unsafe.Pointer(buffer))
	return slice
}
