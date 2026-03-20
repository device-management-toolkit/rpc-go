/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
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
	tunnelMode    bool
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

// SetTunnelMode configures the connection for TLS tunnel passthrough.
// In tunnel mode, Connect() uses plain TCP even when useTls is true,
// because the TLS handshake is handled by RPS through the tunnel.
func (lms *LMSConnection) SetTunnelMode(tunnel bool) {
	lms.tunnelMode = tunnel
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

		if lms.useTls && !lms.tunnelMode {
			log.Debug("connecting to lms over tls...")

			dialer := &tls.Dialer{
				NetDialer: &net.Dialer{Timeout: utils.LMSDialerTimeout * time.Second},
				Config:    certs.GetTLSConfig(&lms.controlMode, nil, lms.skipCertCheck),
			}
			lms.Connection, err = dialer.DialContext(ctx, "tcp4", lms.address+":"+lms.port)
		} else if lms.tunnelMode {
			log.Debug("connecting to lms (tunnel mode)...")

			dialer := &net.Dialer{}
			lms.Connection, err = dialer.DialContext(context.Background(), "tcp4", lms.address+":"+lms.port)
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

	// For TLS tunnel mode, AMT may take 30+ seconds to reconfigure after TLS settings change.
	// Use a longer timeout than RPS's delay_tls_timer (50s) so RPS times out first
	// with a proper error rather than getting connection_reset.
	readTimeout := 500 * time.Millisecond
	subsequentReadTimeout := 100 * time.Millisecond

	if lms.useTls {
		readTimeout = 60 * time.Second
		// For TLS mode, use longer subsequent timeout as AMT may be slow between response chunks
		// especially for operations like AddTrustedRootCertificate that write to non-volatile storage
		subsequentReadTimeout = 2 * time.Second
	}

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)

	for {
		lms.Connection.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := lms.Connection.Read(tmp)
		if err != nil {
			var netErr net.Error
			if err != io.EOF && (!errors.As(err, &netErr) || !netErr.Timeout()) {
				log.Println("LMS read error:", err)
				lms.errors <- err
			}

			break
		}

		buf = append(buf, tmp[:n]...)
		readTimeout = subsequentReadTimeout
	}

	lms.Connection.SetReadDeadline(time.Time{})
	lms.data <- buf

	log.Trace("done listening")
}
