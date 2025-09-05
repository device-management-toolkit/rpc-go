//go:build linux && amt
// +build linux,amt

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

type Version struct {
	MajorNumber uint8
	MinorNumber uint8
}
type CommandFormat struct {
	val    uint32
	fields [3]uint32
}
type MessageHeader struct {
	Version  Version
	Reserved uint16
	Command  CommandFormat
	Length   uint32
}
type GetUUIDRequest struct {
	Header MessageHeader
}

func TestHeciInit(t *testing.T) {
	h := Driver{}
	err := h.Init(false, false)
	defer h.Close()
	assert.NoError(t, err)
	assert.Equal(t, uint32(5120), h.bufferSize)
}

func TestHeciInitLME(t *testing.T) {
	h := Driver{}
	err := h.Init(true, false)
	defer h.Close()
	assert.NoError(t, err)
	assert.Equal(t, uint8(4), h.protocolVersion)
	assert.Equal(t, uint32(8192), h.bufferSize)
}

func TestHeciInitWatchdog(t *testing.T) {
	h := Driver{}
	err := h.Init(false, true)
	defer h.Close()
	assert.NoError(t, err)
	assert.Equal(t, uint32(5120), h.bufferSize)
}

func TestHeciInitError(t *testing.T) {
	h := Driver{}
	err := h.Init(true, false)
	defer h.Close()
	assert.Error(t, err)
}

func TestGetBufferSize(t *testing.T) {
	h := Driver{}
	h.bufferSize = uint32(10)
	result := h.GetBufferSize()
	assert.Equal(t, result, uint32(10))
}

func TestSendMessage(t *testing.T) {
	h := Driver{}
	err := h.Init(false, false)
	defer h.Close()
	assert.NoError(t, err)
	commandSize := (uint32)(12) //(uint32)(unsafe.Sizeof(GetUUIDRequest{}))
	command := GetUUIDRequest{
		Header: MessageHeader{
			Version: Version{
				MajorNumber: 1,
				MinorNumber: 1,
			},
			Reserved: 0,
			Command: CommandFormat{
				val: 0x400005c,
			},
			Length: 0,
		},
	}
	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.LittleEndian, command)
	size, err := h.SendMessage(bin_buf.Bytes(), nil)
	assert.Greater(t, size, commandSize)
	assert.NoError(t, err)
}

func TestReceiveMessage(t *testing.T) {
	h := Driver{}
	err := h.Init(false, false)
	defer h.Close()
	assert.NoError(t, err)
	// send a message so we can receieve it
	commandSize := (uint32)(12) //(uint32)(unsafe.Sizeof(GetUUIDRequest{}))
	command := GetUUIDRequest{
		Header: MessageHeader{
			Version: Version{
				MajorNumber: 1,
				MinorNumber: 1,
			},
			Reserved: 0,
			Command: CommandFormat{
				val: 0x400005c,
			},
			Length: 0,
		},
	}
	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.LittleEndian, command)
	size, err := h.SendMessage(bin_buf.Bytes(), nil)
	assert.Greater(t, size, commandSize)
	assert.NoError(t, err)

	bufferSize := uint32(5120)
	readBuffer := make([]byte, bufferSize)
	bytesRead, err := h.ReceiveMessage(readBuffer, &bufferSize)

	assert.NoError(t, err)
	assert.Positive(t, bytesRead)
}
