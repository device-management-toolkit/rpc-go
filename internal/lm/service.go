/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type LMSConnection struct {
	Connection    net.Conn
	address       string
	port          string
	useTls        bool
	data          chan []byte
	errors        chan error
	controlMode   int
	skipCertCheck bool
	// closing is set by Close() so a streaming reader can tell a deliberate local close
	// (port switch, new TLS handshake, shutdown) from a failure that RPS must hear about.
	closing atomic.Bool
}

// ErrLMSReadTimeoutNoData indicates the socket hit a read timeout before
// receiving any bytes for the current round-trip.
var ErrLMSReadTimeoutNoData = errors.New("lms read timeout with no data")

func NewLMSConnection(address, port string, useTls bool, data chan []byte, errors chan error, mode int, skipCertCheck bool) *LMSConnection {
	lms := &LMSConnection{
		address:       address,
		port:          port,
		useTls:        useTls,
		data:          data,
		errors:        errors,
		controlMode:   mode,
		skipCertCheck: skipCertCheck,
	}

	return lms
}

func (lms *LMSConnection) Initialize() error {
	return errors.New("not implemented")
}

// Connect initializes TCP connection to LMS
func (lms *LMSConnection) Connect() error {
	var err error

	if lms.Connection == nil {
		if lms.useTls {
			log.Debug("connecting to lms (tunnel mode)...")

			dialer := &net.Dialer{}
			lms.Connection, err = dialer.DialContext(context.Background(), "tcp4", lms.address+":"+lms.port)
		} else {
			log.Debug("connecting to lms...")

			dialer := &net.Dialer{}
			lms.Connection, err = dialer.DialContext(context.Background(), "tcp4", lms.address+":"+lms.port)
		}

		if err != nil {
			// handle error
			return err
		}

		// A fresh socket: read errors on it are real until Close() is called again.
		lms.closing.Store(false)
	}

	log.Debug("connected to lms")

	return nil
}

// Send writes data to LMS TCP Socket
func (lms *LMSConnection) Send(data []byte) error {
	_, err := lms.Connection.Write(data)

	return err
}

// Close closes the LMS socket connection
func (lms *LMSConnection) Close() error {
	log.Debug("closing connection to lms")

	// Set before the socket is closed so the streaming reader, which is blocked in Read and
	// will wake with a "use of closed network connection" error, knows this close was ours
	// and must not report it to RPS as a connection reset.
	lms.closing.Store(true)

	if lms.Connection != nil {
		err := lms.Connection.Close()
		if err != nil {
			return err
		}

		lms.Connection = nil
	}

	return nil
}

// Listen reads data from the LMS socket connection.
//
// In TLS-tunnel mode the LMS connection is persistent across multiple tls_data
// round-trips. TLS 1.3 has handshake rounds that legitimately produce zero
// AMT-side bytes (e.g. immediately after our client Finished). To keep those
// quiet rounds from stalling the tunnel and from being misread as a dead
// connection, when useTls is set we:
//   - use a short first-byte timeout, well below RPS's per-operation budget;
//   - signal "silence before first byte" via a typed ErrLMSReadTimeoutNoData on
//     the errors channel, which the executor treats as a non-fatal continuation
//     in TLS-tunnel mode; and
//   - skip the trailing safeSendData(buf) for that case so callers can rely on
//     the typed error path instead of conflating it with EOF / close.
//
// In non-TLS mode the existing behavior is preserved: a read timeout simply
// ends the current message and the accumulated buffer (possibly empty) is
// delivered on the data channel.
func (lms *LMSConnection) Listen() {
	// TLS-tunnel mode: a streaming reader that runs for the life of the connection (see
	// listenStream). The request/response read below, which ends a message after a silence
	// gap, remains for the plain LMS path and is unchanged.
	if lms.useTls {
		lms.listenStream()

		return
	}

	readTimeout := 1500 * time.Millisecond
	subsequentReadTimeout := 1000 * time.Millisecond

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	timedOutNoData := false

	for {
		lms.Connection.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := lms.Connection.Read(tmp)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if lms.useTls && len(buf) == 0 {
					timedOutNoData = true

					lms.safeSendError(ErrLMSReadTimeoutNoData)
				}

				break
			}

			if err != io.EOF {
				log.Println("LMS read error:", err)
				lms.safeSendError(err)
			}

			break
		}

		buf = append(buf, tmp[:n]...)
		readTimeout = subsequentReadTimeout
	}

	lms.Connection.SetReadDeadline(time.Time{})

	if !timedOutNoData {
		lms.safeSendData(buf)
	}
}

// listenStream is the TLS-tunnel reader. The bytes on this socket are TLS records that RPS
// terminates, so rpc-go cannot see HTTP framing and must not try to guess where a response
// ends. It forwards every chunk the moment it arrives and keeps reading for the life of the
// connection; the old mode waited for 1 s of silence after every response, which added about
// one second to every WS-Man call of a provisioning run.
//
// An empty buffer on the data channel means the peer closed the connection (the executor
// turns that into connection_reset). A deliberate local Close() ends the reader silently.
func (lms *LMSConnection) listenStream() {
	conn := lms.Connection
	if conn == nil {
		log.Debug("lms stream reader: no connection")

		return
	}

	log.Debug("listening for lms messages (tls tunnel, streaming)...")

	tmp := make([]byte, 16384)

	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, tmp[:n])
			lms.safeSendData(chunk)
		}

		if err == nil {
			continue
		}

		if lms.closing.Load() {
			log.Debug("lms stream reader exiting after local close")

			return
		}

		if errors.Is(err, io.EOF) {
			log.Debug("lms closed the tunnel connection")
			lms.safeSendData([]byte{})

			return
		}

		log.Println("LMS read error:", err)
		lms.safeSendError(err)

		return
	}
}

// safeSendData sends data to the data channel, recovering from panic if channel is closed
func (lms *LMSConnection) safeSendData(data []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Debug("data channel closed, discarding response")
		}
	}()

	lms.data <- data
}

// safeSendError sends error to the errors channel, recovering from panic if channel is closed
func (lms *LMSConnection) safeSendError(err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Debug("errors channel closed, discarding error")
		}
	}()

	lms.errors <- err
}
