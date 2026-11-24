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
	"sync"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
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
	mu            sync.Mutex
	readerStop    chan struct{}
	generation    uint64
	stream        chan StreamEvent
}

// ErrLMSReadTimeoutNoData indicates the socket hit a read timeout before
// receiving any bytes for the current round-trip. The executor treats this
// as a benign continuation in TLS-tunnel mode (TLS 1.3 has handshake rounds
// where AMT correctly produces zero bytes — e.g. immediately after our
// client Finished — and we must not tear the tunnel down for those).
var ErrLMSReadTimeoutNoData = errors.New("lms read timeout with no data")

// plainFirstByteTimeout bounds how long the non-TLS-tunnel LMS relay waits for
// the first byte of AMT's response to a WSMAN request. Unlike the TLS tunnel,
// the plain relay is strict request/response: every WSMAN message AMT receives
// produces exactly one HTTP response, so there is no legitimate "quiet round"
// to yield on — we must wait for the reply. The activating IPS_HostBasedSetup
// Setup runs provisioning crypto before answering and its first byte can land
// ~1s out (hardware-validated on AMT16/AMT18; the same near-1s ceiling drives
// lmeTunnelFirstByteTimeout and HeciReadTimeout), so a 3s window gives ~3x
// margin while staying under the executor's non-tunnel AMTResponseTimeout (4s)
// budget so the reply is delivered before the response context aborts. The
// earlier 500ms window clipped the Setup response: the read timed out empty,
// the relay closed the socket, RPS never saw the reply, then retried Setup
// against an already-activated device and reported "Failed to activate."
const plainFirstByteTimeout = 3 * time.Second

// tlsFirstByteTimeout is the TLS-tunnel analog: kept short (well below RPS's
// per-operation budget) so a legitimately-silent TLS 1.3 handshake round
// yields promptly via ErrLMSReadTimeoutNoData instead of stalling the tunnel.
const tlsFirstByteTimeout = 2 * time.Second

// plainSubsequentReadTimeout is the idle gap, after the first response byte has
// arrived on the plain relay, used to detect the end of AMT's chunked HTTP
// response. AMT streams the reply contiguously over the loopback socket, so a
// short idle window bounds per-round latency without truncating the body.
const plainSubsequentReadTimeout = 100 * time.Millisecond

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
	lms.mu.Lock()
	defer lms.mu.Unlock()

	if lms.Connection != nil {
		log.Debug("connected to lms")

		return nil
	}

	if lms.useTls {
		log.Debug("connecting to lms (tls port, plain tcp; RPS handles TLS)...")
	} else {
		log.Debug("connecting to lms...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), utils.LMSConnectionTimeout*time.Second)
	defer cancel()

	dialer := &net.Dialer{Timeout: utils.LMSDialerTimeout * time.Second}

	conn, err := dialer.DialContext(ctx, "tcp4", lms.address+":"+lms.port)
	if err != nil {
		return err
	}

	lms.Connection = conn
	lms.readerStop = make(chan struct{})
	lms.generation++

	log.Debug("connected to lms")

	return nil
}

// Send writes data to LMS TCP Socket
func (lms *LMSConnection) Send(data []byte) error {
	// Snapshot the connection under the lock used by Connect and Close.
	// Release it before Write so a blocked send cannot prevent Close.
	lms.mu.Lock()
	conn := lms.Connection
	lms.mu.Unlock()

	if conn == nil {
		return net.ErrClosed
	}

	_, err := conn.Write(data)

	return err
}

// Close closes the LMS socket connection
func (lms *LMSConnection) Close() error {
	lms.mu.Lock()
	defer lms.mu.Unlock()

	log.Debug("closing connection to lms")

	// Set before the socket is closed so the streaming reader, which is blocked in Read and
	// will wake with a "use of closed network connection" error, knows this close was ours
	// and must not report it to RPS as a connection reset.
	if lms.readerStop != nil {
		close(lms.readerStop)
		lms.readerStop = nil
	}

	if lms.Connection != nil {
		err := lms.Connection.Close()
		lms.Connection = nil

		return err
	}

	return nil
}

// Listen reads data from the LMS socket connection.
//
// The first-byte read timeout differs by mode because the two relays have
// opposite silence semantics:
//
//   - Plain (non-TLS-tunnel) relay: strict request/response — every WSMAN
//     message AMT receives yields exactly one HTTP response, so silence is not
//     legitimate; we must wait for the reply. We use plainFirstByteTimeout (3s)
//     so the slow activating Setup response is not clipped. A timeout with no
//     bytes here is a genuinely unresponsive AMT and is surfaced as
//     ErrLMSReadTimeoutNoData for the executor to handle.
//   - TLS-tunnel mode: the connection is persistent across multiple tls_data
//     round-trips and TLS 1.3 has handshake rounds that legitimately produce
//     zero AMT-side bytes (e.g. immediately after our client Finished). We use
//     a short tlsFirstByteTimeout (2s, well below RPS's per-operation budget)
//     and signal "silence before first byte" via ErrLMSReadTimeoutNoData so
//     the executor treats it as a non-fatal continuation and keeps the tunnel
//     alive.
//
// In both modes we skip the trailing `lms.data <- buf` send when we timed out
// with no bytes, so callers rely on the typed error path instead of conflating
// timeout-no-data with EOF/close semantics. The same skip applies when a
// non-timeout read error has been emitted on `lms.errors`, so an empty buf is
// not delivered to `lms.data` afterwards (which the executor would otherwise
// treat as a connection close).
func (lms *LMSConnection) Listen() {
	log.Debug("listening for lms messages...")
	lms.mu.Lock()
	conn := lms.Connection
	lms.mu.Unlock()

	if conn == nil {
		return
	}

	readTimeout := plainFirstByteTimeout
	subsequentReadTimeout := plainSubsequentReadTimeout

	if lms.useTls {
		readTimeout = tlsFirstByteTimeout
		subsequentReadTimeout = tlsFirstByteTimeout
	}

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	timedOutNoData := false
	sentErr := false

	for {
		conn.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := conn.Read(tmp)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if len(buf) == 0 {
					timedOutNoData = true

					lms.errors <- ErrLMSReadTimeoutNoData
				}

				break
			}

			if err != io.EOF {
				log.Println("LMS read error:", err)

				lms.errors <- err

				sentErr = true
			}

			break
		}

		buf = append(buf, tmp[:n]...)
		readTimeout = subsequentReadTimeout
	}

	conn.SetReadDeadline(time.Time{})

	if !timedOutNoData && !sentErr {
		lms.data <- buf
	}

	log.Trace("done listening")
}

// StartTLSStream forwards TLS chunks immediately for the current connection.
// Events carry the connection generation so replaced readers can be ignored.
func (lms *LMSConnection) StartTLSStream() (uint64, <-chan StreamEvent) {
	lms.mu.Lock()
	if lms.readerStop == nil {
		lms.readerStop = make(chan struct{})
		lms.generation++
	}

	conn, stop, generation := lms.Connection, lms.readerStop, lms.generation
	if lms.stream == nil {
		lms.stream = make(chan StreamEvent)
	}

	stream := lms.stream

	lms.mu.Unlock()

	go readStream(conn, stop, func(data []byte, err error) {
		select {
		case <-stop:
			return
		default:
		}

		select {
		case stream <- StreamEvent{Generation: generation, Data: data, Err: err}:
		case <-stop:
		}
	})

	return generation, stream
}

func readStream(conn net.Conn, stop <-chan struct{}, emit func([]byte, error)) {
	if conn == nil {
		log.Debug("lms stream reader: no connection")

		return
	}

	log.Debug("listening for lms messages (tls tunnel, streaming)...")

	tmp := make([]byte, 16384)

	for {
		select {
		case <-stop:
			return
		default:
		}

		n, err := conn.Read(tmp)

		select {
		case <-stop:
			return
		default:
		}

		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, tmp[:n])
			emit(chunk, nil)
		}

		if err == nil {
			continue
		}

		select {
		case <-stop:
			log.Debug("lms stream reader exiting after local close")

			return
		default:
		}

		if errors.Is(err, io.EOF) {
			log.Debug("lms closed the tunnel connection")
			emit(nil, io.EOF)

			return
		}

		log.Println("LMS read error:", err)
		emit(nil, err)

		return
	}
}
