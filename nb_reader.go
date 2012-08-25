package sslconn

import (
	"bytes"
	"io"
	"sync"
)

type NonBlockingReader struct {
	reader        io.Reader
	cap           int
	lock          *sync.Mutex
	buffer        *bytes.Buffer
	readyCond     *sync.Cond
	unblockedCond *sync.Cond
	err           error
	closed        bool
}

func NewNonBlockingReader(reader io.Reader, cap int) *NonBlockingReader {
	r := &NonBlockingReader{}
	r.reader = reader
	r.cap = cap
	r.lock = &sync.Mutex{}
	r.buffer = &bytes.Buffer{}
	r.readyCond = sync.NewCond(r.lock)
	r.unblockedCond = sync.NewCond(r.lock)

	go r.loop()

	return r
}

func (r *NonBlockingReader) WaitUntilReady() {
	r.lock.Lock()
	defer r.lock.Unlock()

	for r.buffer.Len() == 0 && r.err == nil && !r.closed {
		r.readyCond.Wait()
	}
}

func (r *NonBlockingReader) Close() {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.closed {
		return
	}

	r.closed = true
	r.unblockedCond.Signal()
}

func (r *NonBlockingReader) Read(b []byte) (int, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.closed {
		return 0, ErrClosed
	}

	read, _ := r.buffer.Read(b)

	if r.buffer.Len() < r.cap {
		r.unblockedCond.Signal()
	}

	if read == 0 {
		if r.err != nil {
			return 0, r.err
		}
		return 0, ErrAgain
	}
	return read, nil
}

func (r *NonBlockingReader) loop() {
	buffer := make([]byte, r.cap)
	for {
		read, err := r.reader.Read(buffer)

		stop := func() bool {
			r.lock.Lock()
			defer r.lock.Unlock()

			if err != nil {
				r.err = err
				r.readyCond.Broadcast()
				return true
			}

			r.buffer.Write(buffer[:read])
			r.readyCond.Broadcast()

			for r.buffer.Len() >= r.cap && !r.closed {
				r.unblockedCond.Wait()
			}

			if r.closed {
				return true
			}
			return false
		}()

		if stop {
			return
		}
	}
}
