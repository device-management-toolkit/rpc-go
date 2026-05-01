/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package heci

import "errors"

var (
	// ErrDeviceNotInitialized indicates the HECI device handle is unavailable.
	ErrDeviceNotInitialized = errors.New("heci device not initialized")
	// ErrReadTimeout indicates a HECI read operation exceeded its timeout.
	ErrReadTimeout = errors.New("heci read timeout")
)

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
