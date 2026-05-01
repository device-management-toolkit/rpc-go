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
}

// ErrLMSReadTimeoutNoData indicates the socket hit a read timeout before
// receiving any bytes for the current round-trip. The executor treats this
// as a benign continuation in TLS-tunnel mode (TLS 1.3 has handshake rounds
// where AMT correctly produces zero bytes — e.g. immediately after our
// client Finished — and we must not tear the tunnel down for those).
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

	log.Debug("connected to lms")

	return nil
}

// Send writes data to LMS TCP Socket
func (lms *LMSConnection) Send(data []byte) error {
	log.Debug("sending message to LMS")

	_, err := lms.Connection.Write(data)
	if err != nil {
		return err
	}

	log.Debug("sent message to LMS")

	return nil
}

// Close closes the LMS socket connection
func (lms *LMSConnection) Close() error {
	log.Debug("closing connection to lms")

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
// connection, we use a short first-byte timeout (2s, well below RPS's
// per-operation budget) and signal "silence before first byte" via a typed
// ErrLMSReadTimeoutNoData on the errors channel. The executor treats that as
// a non-fatal continuation in tunnel mode. We also skip the trailing
// `lms.data <- buf` send for that case so callers can rely on the typed
// error path instead of conflating timeout-no-data with EOF/close semantics.
// The same skip applies when a non-timeout read error has been emitted on
// `lms.errors`, so an empty buf is not delivered to `lms.data` afterwards
// (which the executor would otherwise treat as a connection close).
func (lms *LMSConnection) Listen() {
	log.Debug("listening for lms messages...")

	readTimeout := 500 * time.Millisecond
	subsequentReadTimeout := 100 * time.Millisecond

	if lms.useTls {
		readTimeout = 2 * time.Second
		subsequentReadTimeout = 2 * time.Second
	}

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	timedOutNoData := false
	sentErr := false

	for {
		lms.Connection.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := lms.Connection.Read(tmp)
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

	lms.Connection.SetReadDeadline(time.Time{})

	if !timedOutNoData && !sentErr {
		lms.data <- buf
	}

	log.Trace("done listening")
}
