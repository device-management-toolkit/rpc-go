/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"errors"
	"sync"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/apf"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/stretchr/testify/assert"
)

type MockHECICommands struct{}

var message []byte
var sendBytesWritten int
var sendError error
var initError error
var bufferSize uint32

func resetMock() {
	message = []byte{}
	sendBytesWritten = 12
	sendError = nil
	initError = nil
	bufferSize = 5120
}

func (c *MockHECICommands) Init(useLME bool, useWD bool) error { return initError }
func (c *MockHECICommands) GetBufferSize() uint32              { return bufferSize } // MaxMessageLength
func (c *MockHECICommands) SendMessage(buffer []byte, done *uint32) (bytesWritten int, err error) {
	return sendBytesWritten, sendError
}
func (c *MockHECICommands) ReceiveMessage(buffer []byte, done *uint32) (bytesRead int, err error) {
	for i := 0; i < len(message) && i < len(buffer); i++ {
		buffer[i] = message[i]
	}

	return len(message), nil
}
func (c *MockHECICommands) Close() {}

var pthiVar pthi.Command

func init() {
	pthiVar = pthi.Command{}
	pthiVar.Heci = &MockHECICommands{}
}
func Test_NewLMEConnection(t *testing.T) {
	resetMock()

	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)
	wg := &sync.WaitGroup{}
	lme := NewLMEConnection(lmDataChannel, lmErrorChannel, wg)
	assert.Equal(t, lmDataChannel, lme.Session.DataBuffer)
	assert.Equal(t, lmErrorChannel, lme.Session.ErrorBuffer)
}
func TestLMEConnection_Initialize(t *testing.T) {
	resetMock()

	testError := errors.New("test error")

	tests := []struct {
		name         string
		sendNumBytes int
		sendErr      error
		initErr      error
		wantErr      bool
	}{
		{
			name:         "Normal",
			sendNumBytes: 93,
			sendErr:      nil,
			initErr:      nil,
			wantErr:      false,
		},
		{
			name:         "ExpectedFailureOnOpen",
			sendNumBytes: 93,
			sendErr:      nil,
			initErr:      testError,
			wantErr:      true,
		},
		{
			name:         "ExpectedFailureOnExecute",
			sendNumBytes: 93,
			sendErr:      testError,
			initErr:      nil,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sendBytesWritten = tt.sendNumBytes
			sendError = tt.sendErr
			initError = tt.initErr

			lme := &LMEConnection{
				Command: pthiVar,
				Session: &apf.Session{
					WaitGroup: &sync.WaitGroup{},
				},
				ourChannel: 1,
			}
			if err := lme.Initialize(); (err != nil) != tt.wantErr {
				t.Errorf("LMEConnection.Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Send(t *testing.T) {
	resetMock()

	sendBytesWritten = 14

	lme := &LMEConnection{
		Command: pthiVar,
		Session: &apf.Session{
			WaitGroup: &sync.WaitGroup{},
		}, ourChannel: 1,
	}
	data := []byte("hello")
	err := lme.Send(data)
	assert.NoError(t, err)
}
func Test_Connect(t *testing.T) {
	resetMock()

	sendBytesWritten = 54
	lme := &LMEConnection{
		Command: pthiVar,
		Session: &apf.Session{
			WaitGroup: &sync.WaitGroup{},
		},
		ourChannel: 1,
	}
	err := lme.Connect()
	assert.NoError(t, err)
}
func Test_Connect_With_Error(t *testing.T) {
	resetMock()

	sendError = errors.New("no such device")
	sendBytesWritten = 54
	lme := &LMEConnection{
		Command: pthiVar,
		Session: &apf.Session{
			WaitGroup: &sync.WaitGroup{},
		},
		ourChannel: 1,
	}
	err := lme.Connect()
	assert.Error(t, err)
}
func Test_Listen(t *testing.T) {
	resetMock()

	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	lme := &LMEConnection{
		Command: pthiVar,
		Session: &apf.Session{
			DataBuffer:  lmDataChannel,
			ErrorBuffer: lmErrorChannel,
			Status:      make(chan bool),
			WaitGroup:   &sync.WaitGroup{},
		},
		ourChannel: 1,
	}
	message = []byte{0x94, 0x01}

	defer lme.Close()

	go lme.Listen()
}

func Test_Close(t *testing.T) {
	resetMock()

	lme := &LMEConnection{
		Command:    pthiVar,
		Session:    &apf.Session{},
		ourChannel: 1,
	}
	err := lme.Close()
	assert.NoError(t, err)
}
func Test_CloseWithChannel(t *testing.T) {
	resetMock()

	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	lme := &LMEConnection{
		Command: pthiVar,
		Session: &apf.Session{
			DataBuffer:  lmDataChannel,
			ErrorBuffer: lmErrorChannel,
			Status:      make(chan bool),
		},
		ourChannel: 1,
	}
	err := lme.Close()
	assert.NoError(t, err)
}
