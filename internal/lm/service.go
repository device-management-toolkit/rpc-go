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
	data          chan []byte
	errors        chan error
	controlMode   int
	skipCertCheck bool
}

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
		ctx, cancel := context.WithTimeout(context.Background(), utils.LMSConnectionTimeout*time.Second)
		defer cancel()

		if lms.useTls {
			log.Debug("connecting to lms over tls...")

			dialer := &tls.Dialer{
				NetDialer: &net.Dialer{Timeout: utils.LMSDialerTimeout * time.Second},
				Config:    certs.GetTLSConfig(&lms.controlMode, nil, lms.skipCertCheck),
			}
			lms.Connection, err = dialer.DialContext(ctx, "tcp4", lms.address+":"+lms.port)
		} else {
			log.Debug("connecting to lms...")

			dialer := &net.Dialer{Timeout: utils.LMSDialerTimeout * time.Second}
			lms.Connection, err = dialer.DialContext(ctx, "tcp4", lms.address+":"+lms.port)
		}

		if err != nil {
			// handle error
			return err
		}
	}

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

// Listen reads data from the LMS socket connection
func (lms *LMSConnection) Listen() {
	log.Debug("listening for lms messages...")

	readIdleTimeout := utils.LMSReadIdleTimeout * time.Second

	buf := make([]byte, 0, 8192) // big buffer
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

				continue
			}

			if err != io.EOF {
				log.Println("read error:", err)

				lms.errors <- err

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
		return bytes.Contains(body, []byte("\r\n0\r\n\r\n"))
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
