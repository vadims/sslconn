package sslconn

import (
	"bytes"
	"io"
	"sync"
)

type NonBlockingWriter struct {
	writer        io.Writer
	cap           int
	lock          *sync.Mutex
	buffer        *bytes.Buffer
	readyCond     *sync.Cond
	unblockedCond *sync.Cond
	closedChan    chan bool
	err           error
	closed        bool
}

func NewNonBlockingWriter(writer io.Writer, cap int) *NonBlockingWriter {
	w := &NonBlockingWriter{}
	w.writer = writer
	w.cap = cap
	w.lock = &sync.Mutex{}
	w.buffer = &bytes.Buffer{}
	w.readyCond = sync.NewCond(w.lock)
	w.unblockedCond = sync.NewCond(w.lock)
	w.closedChan = make(chan bool, 1)

	go w.loop()

	return w
}

func (w *NonBlockingWriter) WaitUntilReady() {
	w.lock.Lock()
	defer w.lock.Unlock()

	for w.cap-w.buffer.Len() == 0 && w.err == nil && !w.closed {
		w.readyCond.Wait()
	}
}

func (w *NonBlockingWriter) Close() {
	w.lock.Lock()

	if w.closed {
		w.lock.Unlock()
		return
	}

	w.closed = true
	w.unblockedCond.Signal()
	w.lock.Unlock()

	<-w.closedChan
}

func (w *NonBlockingWriter) Write(b []byte) (int, error) {
	w.lock.Lock()
	defer w.lock.Unlock()

	if w.closed {
		return 0, ErrClosed
	}

	if w.err != nil {
		return 0, w.err
	}

	space := w.cap - w.buffer.Len()
	if space <= 0 {
		return 0, ErrAgain
	}

	wrote := len(b)
	if wrote > space {
		wrote = space
	}

	w.buffer.Write(b[:wrote])
	w.unblockedCond.Signal()
	return wrote, nil
}

func (w *NonBlockingWriter) loop() {
	buffer := make([]byte, w.cap)
	for {
		stop := func() bool {
			w.lock.Lock()
			defer w.lock.Unlock()

			read := 0
			for {
				read, _ = w.buffer.Read(buffer)
				if read > 0 {
					break
				}
				if w.closed {
					return true
				}
				w.unblockedCond.Wait()
			}

			w.readyCond.Broadcast()
			w.lock.Unlock()

			err := writeBytesTo(buffer[:read], w.writer)

			w.lock.Lock()
			if err != nil {
				w.err = err
				w.readyCond.Broadcast()
				return true
			}
			return false
		}()

		if stop {
			w.closedChan <- true
			return
		}
	}
}
