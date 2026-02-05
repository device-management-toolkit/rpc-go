/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"errors"
	"io"
	"net"
	"strings"
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
	return errors.New("not implemented5")
}

// Connect initializes TCP connection to LMS
func (lms *LMSConnection) Connect() error {
	var err error

	if lms.Connection == nil {
		if lms.useTls {
			log.Debug("connecting to lms over tls...")

			//lms.Connection, err = tls.Dial("tcp4", lms.address+":"+lms.port, config.GetTLSConfig(&lms.controlMode, nil, lms.skipCertCheck))
			lms.Connection, err = net.Dial("tcp4", lms.address+":"+lms.port)

		} else {
			log.Debug("connecting to lms...")

			lms.Connection, err = net.Dial("tcp4", lms.address+":"+lms.port)
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
	_, err := lms.Connection.Write(data)
	return err
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
	// For TLS mode, AMT may take 30+ seconds to reconfigure after TLS settings change.
	// Use a longer timeout than RPS's delay_tls_timer (50s) so RPS times out first
	// with a proper error rather than getting connection_reset.
	readTimeout := 500 * time.Millisecond
	if lms.useTls {
		readTimeout = 60 * time.Second
	}

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)

	for {
		lms.Connection.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := lms.Connection.Read(tmp)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "i/o timeout") {
				log.Println("LMS read error:", err)
				lms.safeSendError(err)
			}
			break
		}

		buf = append(buf, tmp[:n]...)
		readTimeout = 100 * time.Millisecond
	}

	lms.Connection.SetReadDeadline(time.Time{})
	lms.safeSendData(buf)
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
