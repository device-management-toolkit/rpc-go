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
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestMeiDevicePathsOrder pins the LMS-style probe order: /dev/mei0..3 ascending.
func TestMeiDevicePathsOrder(t *testing.T) {
	expected := []string{"/dev/mei0", "/dev/mei1", "/dev/mei2", "/dev/mei3"}
	assert.Equal(t, expected, meiDevicePaths)
}

// TestOpenAndConnectNoDevices verifies that when no MEI node exists the probe
// reports a not-found error and leaves no dangling handle on the driver.
func TestOpenAndConnectNoDevices(t *testing.T) {
	orig := meiDevicePaths
	defer func() { meiDevicePaths = orig }()

	dir := t.TempDir()
	meiDevicePaths = []string{
		filepath.Join(dir, "mei0"),
		filepath.Join(dir, "mei1"),
	}

	h := Driver{}
	data := CMEIConnectClientData{data: MEI_IAMTHIF}
	err := h.openAndConnect(&data)

	assert.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	assert.Nil(t, h.meiDevice)
}

// TestOpenAndConnectSkipsNonClientDevice verifies that a node which opens but is
// not a real MEI client (the connect ioctl fails) is closed and skipped rather
// than left open.
func TestOpenAndConnectSkipsNonClientDevice(t *testing.T) {
	orig := meiDevicePaths
	defer func() { meiDevicePaths = orig }()

	dir := t.TempDir()
	fake := filepath.Join(dir, "mei0")
	require.NoError(t, os.WriteFile(fake, []byte{}, 0o600))
	meiDevicePaths = []string{fake}

	h := Driver{}
	data := CMEIConnectClientData{data: MEI_IAMTHIF}
	err := h.openAndConnect(&data)

	assert.Error(t, err)
	assert.Nil(t, h.meiDevice)
}

// TestOpenAndConnectAdvancesPastMissingDevice verifies the probe moves on from a
// missing node to the next candidate instead of stopping at the first gap.
func TestOpenAndConnectAdvancesPastMissingDevice(t *testing.T) {
	orig := meiDevicePaths
	defer func() { meiDevicePaths = orig }()

	dir := t.TempDir()
	present := filepath.Join(dir, "mei1")
	require.NoError(t, os.WriteFile(present, []byte{}, 0o600))

	// First node is absent; second exists but is not a real MEI client.
	meiDevicePaths = []string{filepath.Join(dir, "mei0"), present}

	h := Driver{}
	data := CMEIConnectClientData{data: MEI_IAMTHIF}
	err := h.openAndConnect(&data)

	// Reached the second node (open ok, ioctl failed), so the error is the
	// ioctl failure, not NotExist - proving it advanced past the missing node.
	assert.Error(t, err)
	assert.NotErrorIs(t, err, fs.ErrNotExist)
	assert.Nil(t, h.meiDevice)
}

// TestInitNoDevices verifies Init surfaces an error (and no handle) when the
// probe finds no usable MEI device.
func TestInitNoDevices(t *testing.T) {
	orig := meiDevicePaths
	defer func() { meiDevicePaths = orig }()

	meiDevicePaths = []string{filepath.Join(t.TempDir(), "missing")}

	h := Driver{}
	err := h.Init(false, false)

	assert.Error(t, err)
	assert.Nil(t, h.meiDevice)
}
