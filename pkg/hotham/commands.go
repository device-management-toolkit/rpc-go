/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package hotham

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
)

type Command struct {
	Heci heci.Interface
}

type Interface interface {
	Open() error
	Close()
	Call(command []byte, commandSize int) (result []byte, err error)
	GetFlogSize() (size uint32, err error)
	GetFlog() (flogData []byte, err error)
}

func NewCommand() Command {
	return Command{
		Heci: heci.NewDriver(),
	}
}

func (hotham Command) Open() error {
	return hotham.Heci.InitHOTHAM()
}

func (hotham Command) Close() {
	hotham.Heci.Close()
}

func (hotham Command) Call(command []byte, commandSize int) (result []byte, err error) {
	if commandSize < 0 || uint64(commandSize) > math.MaxInt32 {
		return nil, fmt.Errorf("buffer length exceeds uint32 maximum value")
	}

	// Send the actual command bytes
	actualCommandSize := uint32(len(command))

	bytesWritten, err := hotham.Heci.SendMessage(command, &actualCommandSize)
	if err != nil {
		return nil, err
	}

	if bytesWritten != len(command) {
		return nil, errors.New("failed to send complete message")
	}

	buffer := make([]byte, hotham.Heci.GetBufferSize())

	// Receive up to the expected response size
	// Add retry logic with small delays for HOTHAM interface
	expectedResponseSize := uint32(commandSize)

	var bytesRead int

	maxRetries := 5

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			sleepTime := time.Duration(attempt*10) * time.Millisecond
			time.Sleep(sleepTime)
		}

		bytesRead, err = hotham.Heci.ReceiveMessage(buffer, &expectedResponseSize)
		if err != nil {
			continue
		}

		if bytesRead > 0 {
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("after %d retries: %v", maxRetries, err)
	}

	if bytesRead <= 0 {
		return nil, errors.New("empty response received")
	}

	return buffer[:bytesRead], nil
}

// GetFlogSize retrieves the size of the Flash Log
// Returns total size of records in flash log
// Uses 4-byte HOTHAM header through HOTHAM GUID connection
func (hotham Command) GetFlogSize() (size uint32, err error) {
	// Create request with 4-byte HOTHAM header
	header := NewHOTHAMHeader(PCH_DFX_FLOG_GET_SIZE)
	request := GetFlogSizeRequest{Header: header}

	// Pack the HOTHAM header (4 bytes)
	requestBytes := request.Header.Pack()

	// Send request and receive response
	// Expected response: 4 byte header + 2 byte uint16 size = 6 bytes
	response, err := hotham.Call(requestBytes, 6)
	if err != nil {
		log.Errorf("GetFlogSize: HOTHAM Call failed: %v", err)

		return 0, err
	}

	// Response should be at least 6 bytes (4 byte HOTHAM header + 2 byte size)
	if len(response) < 6 {
		log.Errorf("GetFlogSize: Invalid response size: got %d bytes, expected at least 6", len(response))

		// Check if this is an error response
		if len(response) == 4 {
			log.Errorf("GetFlogSize: Got 4-byte response: %02x %02x %02x %02x",
				response[0], response[1], response[2], response[3])

			// Parse as HOTHAM header to extract error code
			var respHeader HOTHAMHeader
			respHeader.Unpack(response)
			log.Errorf("GetFlogSize: Response - MsgClass=%d TargetId=%d SeqNo=%d ReqCode=0x%02x MsgLen=%d",
				respHeader.MsgClass, respHeader.TargetId, respHeader.SequenceNo, respHeader.ReqCode, respHeader.MsgLength)

			// Check for common error codes
			if response[3] == 0x89 {
				return 0, fmt.Errorf("FLOG command not supported (error 0x89)")
			}
		}

		return 0, fmt.Errorf("invalid response size: got %d bytes, expected at least 6", len(response))
	}

	// Parse response: [Header(4 bytes)][Size(2 bytes as uint16)]
	// Size is at bytes 4-5 (little-endian uint16)
	flogSize := uint32(response[4]) | (uint32(response[5]) << 8)

	log.Tracef("GetFlogSize: FLOG size = %d bytes (0x%x)", flogSize, flogSize)

	return flogSize, nil
}

// GetFlog retrieves the Flash Log data
// Returns flash log records (up to buffer size)
// Uses 4-byte HOTHAM header through HOTHAM GUID connection
func (hotham Command) GetFlog() (flogData []byte, err error) {
	// Create request with 4-byte HOTHAM header
	header := NewHOTHAMHeader(PCH_DFX_FLOG_GET_LOG)
	request := GetFlogRequest{Header: header}

	// Pack the HOTHAM header (4 bytes)
	requestBytes := request.Header.Pack()

	// Send request and receive response
	// Expected response: 8196 bytes (4 byte header + 8192 byte data)
	expectedSize := 8196

	response, err := hotham.Call(requestBytes, expectedSize)
	if err != nil {
		log.Errorf("GetFlog: HOTHAM Call failed: %v", err)

		return nil, err
	}

	// Parse response - skip header (4 bytes) and return data
	if len(response) < 4 {
		log.Errorf("GetFlog: Invalid response size: got %d bytes, expected at least 4", len(response))

		return nil, fmt.Errorf("invalid response size: got %d bytes, expected at least 4", len(response))
	}

	// Parse response header to check for errors
	var respHeader HOTHAMHeader
	respHeader.Unpack(response)

	// Check if response indicates success (MsgLength should contain data length)
	if respHeader.MsgLength == 0 && len(response) == 4 {
		log.Errorf("GetFlog: Got HOTHAM error response with no data")

		return nil, fmt.Errorf("HOTHAM error: empty response")
	}

	// The flash log data starts after the 4-byte HOTHAM header
	flogData = response[4:]

	return flogData, nil
}
