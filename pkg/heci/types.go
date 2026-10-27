/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package heci

type Interface interface {
	Init(useLME, useWD bool) error
	// InitWithGUID connects to the MEI client identified by guid, given in
	// registry form, e.g. "{92136C79-5FEA-4CFD-980E-23BE07FA5E9F}".
	InitWithGUID(guid string) error
	GetBufferSize() uint32
	SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error)
	ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error)
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
