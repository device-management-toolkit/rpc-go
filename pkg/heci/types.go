/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package heci

import (
	"errors"
	"strings"
)

var (
	// ErrDeviceNotInitialized indicates the HECI device handle is unavailable.
	ErrDeviceNotInitialized = errors.New("heci device not initialized")
	// ErrReadTimeout indicates a HECI read operation exceeded its timeout.
	ErrReadTimeout = errors.New("heci read timeout")
	// ErrDeviceReinitialized indicates the HECI device was transparently
	// reopened mid-operation (typically after ENODEV). Stateful callers (LME,
	// which tracks per-session APF channel ids) must re-handshake and retry
	// rather than reuse their pre-reinit state.
	ErrDeviceReinitialized = errors.New("heci device reinitialized, retry required")
)

// IsReadTimeout reports whether err is a HECI read timeout. It matches the
// ErrReadTimeout sentinel via errors.Is and also accepts an error whose message
// contains the sentinel text, so callers that only have a string-wrapped error
// (e.g. one that crossed a boundary that lost the wrap chain) still classify it
// as a benign read timeout.
func IsReadTimeout(err error) bool {
	return errors.Is(err, ErrReadTimeout) || (err != nil && strings.Contains(err.Error(), ErrReadTimeout.Error()))
}

type Interface interface {
	Init(useLME, useWD bool) error
	InitWithGUID(guid interface{}) error
	InitHOTHAM() error
	GetBufferSize() uint32
	SendMessage(buffer []byte, done *uint32) (bytesWritten int, err error)
	ReceiveMessage(buffer []byte, done *uint32) (bytesRead int, err error)
	Close()
}

type MEIConnectClientData struct {
	MaxMessageLength uint32
	ProtocolVersion  uint8
	Reserved         [3]uint8
}

type CMEIConnectClientData struct {
	data [16]byte
}
