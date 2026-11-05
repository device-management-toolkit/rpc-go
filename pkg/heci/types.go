/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package heci

type Interface interface {
	Init(useLME, useWD bool) error
	GetBufferSize() uint32
	SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error)
	ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error)
	Close()
}

// GUIDInterface adds arbitrary MEI client initialization without extending the
// existing Interface contract used by PTHI and LME drivers.
type GUIDInterface interface {
	Interface
	// InitWithGUID accepts a GUID in registry form, with optional braces.
	InitWithGUID(guid string) error
}

type MEIConnectClientData struct {
	MaxMessageLength uint32
	ProtocolVersion  uint8
	Reserved         [3]uint8
}

type CMEIConnectClientData struct {
	data [16]byte
}
