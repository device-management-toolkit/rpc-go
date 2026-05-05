/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type LMSConnection struct {
	Connection    net.Conn
	address       string
	port          string
	useTls        bool
	tlsTunnel     bool
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

func (lms *LMSConnection) SetTLSTunnelMode(enabled bool) {
	lms.tlsTunnel = enabled
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

	if lms.useTls && !lms.tlsTunnel {
		log.Debug("connecting to lms over TLS...")
	} else if lms.tlsTunnel {
		log.Debug("connecting to lms (tls port, plain tcp; RPS handles TLS)...")
	} else {
		log.Debug("connecting to lms...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), utils.LMSConnectionTimeout*time.Second)
	defer cancel()

	dialer := &net.Dialer{Timeout: utils.LMSDialerTimeout * time.Second}

	var (
		conn net.Conn
		err  error
	)

	if lms.useTls && !lms.tlsTunnel {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    certs.GetTLSConfig(&lms.controlMode, nil, lms.skipCertCheck),
		}

		conn, err = tlsDialer.DialContext(ctx, "tcp4", lms.address+":"+lms.port)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp4", lms.address+":"+lms.port)
	}

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
// connection, we signal "silence before first byte" via typed
// ErrLMSReadTimeoutNoData on the errors channel. The executor treats that as
// a non-fatal continuation in tunnel mode. We also skip the trailing
// `lms.data <- buf` send for timeout-no-data and for non-timeout read errors so
// callers can distinguish timeout-no-data from EOF/close semantics.
// The same skip applies when a non-timeout read error has been emitted on
// `lms.errors`, so an empty buf is not delivered to `lms.data` afterwards
// (which the executor would otherwise treat as a connection close).
func (lms *LMSConnection) Listen() {
	log.Debug("listening for lms messages...")

	readIdleTimeout := utils.LMSReadIdleTimeout * time.Second

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	errOccurred := false

	for {
		_ = lms.Connection.SetReadDeadline(time.Now().Add(readIdleTimeout))

		n, err := lms.Connection.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)

			if isCompleteHTTPResponse(buf) {
				break
			}
		}

		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if len(buf) > 0 {
					// For HTTP responses, require completeness before breaking to avoid
					// forwarding truncated bodies (e.g. slow Content-Length delivery).
					// For non-HTTP data (raw protocol), break on any data as before.
					if !strings.HasPrefix(string(buf), "HTTP/") || isCompleteHTTPResponse(buf) {
						break
					}
				}

				if lms.tlsTunnel {
					select {
					case lms.errors <- ErrLMSReadTimeoutNoData:
					default:
					}

					return
				}

				continue
			}

			if err != io.EOF {
				log.Println("read error:", err)

				select {
				case lms.errors <- err:
				default:
				}

				errOccurred = true
			}

			break
		}
	}

	if errOccurred {
		return
	}

	if len(buf) == 0 {
		log.Trace("Sending empty LMS response to data channel (AMT closed connection with no data)")
	}

	lms.data <- buf

	log.Trace("done listening")
}

func isCompleteHTTPResponse(buf []byte) bool {
	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return false
	}

	headers := string(buf[:headerEnd])
	body := buf[headerEnd+4:]
	lowerHeaders := strings.ToLower(headers)

	if strings.Contains(lowerHeaders, "transfer-encoding: chunked") {
		return isCompleteChunkedBody(body)
	}

	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			value := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "content-length:"))

			contentLen, err := strconv.Atoi(value)
			if err != nil {
				return false
			}

			return len(body) >= contentLen
		}
	}

	// No Content-Length and not chunked: only treat as complete for status codes
	// that are defined to have no body (1xx, 204, 304). For all others, the body
	// is delimited by connection close, so return false and let EOF signal completion.
	statusLine := strings.SplitN(headers, "\r\n", 2)[0]
	parts := strings.SplitN(statusLine, " ", 3)

	if len(parts) >= 2 {
		statusCode, err := strconv.Atoi(parts[1])
		if err == nil {
			if (statusCode >= 100 && statusCode < 200) || statusCode == 204 || statusCode == 304 {
				return true
			}
		}
	}

	return false
}

func isCompleteChunkedBody(body []byte) bool {
	if bytes.HasSuffix(body, []byte("0\r\n\r\n")) {
		return true
	}

	if !bytes.HasSuffix(body, []byte("\r\n\r\n")) {
		return false
	}

	lastZeroChunk := bytes.LastIndex(body, []byte("0\r\n"))
	if lastZeroChunk < 0 || lastZeroChunk+3 > len(body)-4 {
		return false
	}

	trailers := body[lastZeroChunk+3 : len(body)-4]
	for len(trailers) > 0 {
		lineEnd := bytes.Index(trailers, []byte("\r\n"))
		if lineEnd <= 0 {
			return false
		}

		if !bytes.Contains(trailers[:lineEnd], []byte(":")) {
			return false
		}

		trailers = trailers[lineEnd+2:]
	}

	return true
}
