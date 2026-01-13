/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package hotham

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
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

	commandSizeUint32 := uint32(commandSize)

	bytesWritten, err := hotham.Heci.SendMessage(command, &commandSizeUint32)
	if err != nil {
		return nil, err
	}

	if bytesWritten != len(command) {
		return nil, errors.New("amt internal error")
	}

	buffer := make([]byte, hotham.Heci.GetBufferSize())

	bytesRead, err := hotham.Heci.ReceiveMessage(buffer, &commandSizeUint32)
	if err != nil {
		return nil, err
	}

	if bytesRead <= 0 {
		return nil, errors.New("empty response from AMT")
	}

	return buffer[:bytesRead], nil
}

// GetFlogSize retrieves the size of the Flash Log
// Reference: HothamCtlGetFlogSize (Id: 0x80, 0x2)
// Returns total size of records in flash log
func (hotham Command) GetFlogSize() (size uint32, err error) {
	// Create request with HOTHAM header
	request := GetFlogSizeRequest{
		Header: HOTHAMHeader{
			Command:  HOTHAM_CMD_GET_FLOG_SIZE,
			Reserved: 0,
			Group:    HOTHAM_GROUP_ID,
			Length:   0, // No additional data
		},
	}

	// Serialize request
	buf := new(bytes.Buffer)

	err = binary.Write(buf, binary.LittleEndian, request.Header)
	if err != nil {
		return 0, err
	}

	requestBytes := buf.Bytes()

	// Send request and receive response
	response, err := hotham.Call(requestBytes, len(requestBytes))
	if err != nil {
		return 0, err
	}

	// Parse response
	if len(response) < 8 { // Header (4 bytes) + Size (4 bytes)
		return 0, errors.New("invalid response size")
	}

	var responseData GetFlogSizeResponse

	responseBuf := bytes.NewReader(response)
	err = binary.Read(responseBuf, binary.LittleEndian, &responseData.Header)

	if err != nil {
		return 0, err
	}

	err = binary.Read(responseBuf, binary.LittleEndian, &responseData.Size)
	if err != nil {
		return 0, err
	}

	return responseData.Size, nil
}

// GetFlog retrieves the Flash Log data
// Reference: HothamCtlGetFlog (Id: 0x81, 0x2)
// Returns flash log records up to 4096 bytes
func (hotham Command) GetFlog() (flogData []byte, err error) {
	// Create request with HOTHAM header
	request := GetFlogRequest{
		Header: HOTHAMHeader{
			Command:  HOTHAM_CMD_GET_FLOG,
			Reserved: 0,
			Group:    HOTHAM_GROUP_ID,
			Length:   0, // No additional data in request
		},
	}

	// Serialize request
	buf := new(bytes.Buffer)

	err = binary.Write(buf, binary.LittleEndian, request.Header)

	if err != nil {
		return nil, err
	}

	requestBytes := buf.Bytes()

	// Send request and receive response
	response, err := hotham.Call(requestBytes, len(requestBytes))
	if err != nil {
		return nil, err
	}

	// Parse response - skip header (4 bytes) and return data
	if len(response) < 4 {
		return nil, errors.New("invalid response size")
	}

	// The flash log data starts after the 4-byte header
	flogData = response[4:]

	return flogData, nil
}
