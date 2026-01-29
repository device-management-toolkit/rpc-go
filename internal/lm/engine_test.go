/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/apf"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/stretchr/testify/assert"
)

type MockHECICommands struct{}

var (
	message          []byte
	sendBytesWritten uint32
	sendError        error
	initError        error
	bufferSize       uint32
)

func resetMock() {
	message = []byte{}
	sendBytesWritten = 12
	sendError = nil
	initError = nil
	bufferSize = 5120
}

func (c *MockHECICommands) Init(useLME, useWD bool) error { return initError }
func (c *MockHECICommands) GetBufferSize() uint32         { return bufferSize } // MaxMessageLength
func (c *MockHECICommands) SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error) {
	return sendBytesWritten, sendError
}

func (c *MockHECICommands) ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error) {
	for i := 0; i < len(message) && i < len(buffer); i++ {
		buffer[i] = message[i]
	}

	return uint32(len(message)), nil
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
		sendNumBytes uint32
		sendErr      error
		initErr      error
		wantErr      bool
	}{
		{
			name:         "Normal",
			sendNumBytes: uint32(93),
			sendErr:      nil,
			initErr:      nil,
			wantErr:      false,
		},
		{
			name:         "ExpectedFailureOnOpen",
			sendNumBytes: uint32(93),
			sendErr:      nil,
			initErr:      testError,
			wantErr:      true,
		},
		{
			name:         "ExpectedFailureOnExecute",
			sendNumBytes: uint32(93),
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

// MockPTHICommand is a mock implementation of pthi.Interface for testing execute method
type MockHECI struct {
	CallFunc    func(command []byte, commandSize uint32) (result []byte, err error)
	CallCount   int
	SendFunc    func(buffer []byte, done *uint32) (uint32, error)
	ReceiveFunc func(buffer []byte, done *uint32) (uint32, error)
	InitFunc    func(useLME bool, useWD bool) error
	CloseFunc   func()
}

func (m *MockHECI) Init(useLME bool, useWD bool) error {
	if m.InitFunc != nil {
		return m.InitFunc(useLME, useWD)
	}

	return nil
}

func (m *MockHECI) GetBufferSize() uint32 {
	return 5120
}

func (m *MockHECI) SendMessage(buffer []byte, done *uint32) (bytesWritten uint32, err error) {
	if m.SendFunc != nil {
		return m.SendFunc(buffer, done)
	}

	return uint32(len(buffer)), nil
}

func (m *MockHECI) ReceiveMessage(buffer []byte, done *uint32) (bytesRead uint32, err error) {
	if m.ReceiveFunc != nil {
		return m.ReceiveFunc(buffer, done)
	}

	return 0, nil
}

func (m *MockHECI) Close() {
	if m.CloseFunc != nil {
		m.CloseFunc()
	}
}

// MockPTHIInterface for execute testing
type MockPTHIInterface struct {
	CallFunc  func(command []byte, commandSize uint32) (result []byte, err error)
	CallCount int
	mu        sync.Mutex
}

func (m *MockPTHIInterface) Call(command []byte, commandSize uint32) (result []byte, err error) {
	m.mu.Lock()
	m.CallCount++
	m.mu.Unlock()

	if m.CallFunc != nil {
		return m.CallFunc(command, commandSize)
	}

	return nil, nil
}

func TestLMEConnection_Execute_Success(t *testing.T) {
	mockHECI := &MockHECI{
		InitFunc: func(useLME, useWD bool) error {
			return nil
		},
		SendFunc: func(buffer []byte, done *uint32) (uint32, error) {
			// Return the length of buffer to pass the validation
			return uint32(len(buffer)), nil
		},
		ReceiveFunc: func(buffer []byte, done *uint32) (uint32, error) {
			// Return 0 bytes to trigger completion
			return 0, errors.New("empty response from AMT")
		},
	}

	command := pthi.Command{Heci: mockHECI}

	lme := &LMEConnection{
		Command: command,
		Session: &apf.Session{
			WaitGroup: &sync.WaitGroup{},
		},
	}

	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.BigEndian, uint32(1))

	err := lme.execute(bin_buf)
	assert.NoError(t, err)
}

func TestLMEConnection_Execute_RecoverableError(t *testing.T) {
	tests := []struct {
		name     string
		errorMsg string
	}{
		{
			name:     "EmptyResponseFromAMT",
			errorMsg: "empty response from AMT",
		},
		{
			name:     "NoSuchDevice",
			errorMsg: "no such device",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHECI := &MockHECI{
				InitFunc: func(useLME, useWD bool) error {
					return nil
				},
				SendFunc: func(buffer []byte, done *uint32) (uint32, error) {
					return 0, errors.New(tt.errorMsg)
				},
			}

			command := pthi.Command{Heci: mockHECI}

			lme := &LMEConnection{
				Command: command,
				Session: &apf.Session{
					WaitGroup: &sync.WaitGroup{},
				},
			}

			var bin_buf bytes.Buffer
			binary.Write(&bin_buf, binary.BigEndian, uint32(1))

			err := lme.execute(bin_buf)
			assert.NoError(t, err)
		})
	}
}

func TestLMEConnection_Execute_NonRecoverableError(t *testing.T) {
	expectedError := errors.New("unexpected error")
	mockHECI := &MockHECI{
		InitFunc: func(useLME, useWD bool) error {
			return nil
		},
		SendFunc: func(buffer []byte, done *uint32) (uint32, error) {
			return 0, expectedError
		},
	}

	command := pthi.Command{Heci: mockHECI}

	lme := &LMEConnection{
		Command: command,
		Session: &apf.Session{
			WaitGroup: &sync.WaitGroup{},
		},
	}

	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.BigEndian, uint32(1))

	err := lme.execute(bin_buf)
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
}

func TestLMEConnection_Execute_Timeout(t *testing.T) {
	// Temporarily reduce timeout for faster test execution
	originalTimeout := executionTimeout

	defer func() {
		// Note: Can't actually change the const, so this test uses the real timeout
		// In a real scenario, we'd make executionTimeout configurable
		_ = originalTimeout
	}()

	mockHECI := &MockHECI{
		InitFunc: func(useLME, useWD bool) error {
			return nil
		},
		SendFunc: func(buffer []byte, done *uint32) (uint32, error) {
			// Block for longer than the timeout
			time.Sleep(executionTimeout + 1*time.Second)

			return 0, nil
		},
	}

	command := pthi.Command{Heci: mockHECI}

	lme := &LMEConnection{
		Command: command,
		Session: &apf.Session{
			WaitGroup: &sync.WaitGroup{},
		},
	}

	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.BigEndian, uint32(1))

	start := time.Now()
	err := lme.execute(bin_buf)
	duration := time.Since(start)

	// Should return without error but due to timeout
	assert.NoError(t, err)
	// Should not wait for the full sleep duration
	assert.Less(t, duration, executionTimeout+1*time.Second)
	// Should wait approximately the timeout duration
	assert.GreaterOrEqual(t, duration, executionTimeout)
}

func TestLMEConnection_Execute_APFProtocolSequence(t *testing.T) {
	// Simulate a realistic APF protocol exchange sequence
	callCount := 0
	mockHECI := &MockHECI{
		InitFunc: func(useLME, useWD bool) error {
			return nil
		},
		SendFunc: func(buffer []byte, done *uint32) (uint32, error) {
			return uint32(len(buffer)), nil
		},
		ReceiveFunc: func(buffer []byte, done *uint32) (uint32, error) {
			callCount++
			switch callCount {
			case 1:
				// First call: Return APF_PROTOCOL_VERSION response
				response := []byte{
					0xC0,                   // MessageType: 192 (APF_PROTOCOL_VERSION)
					0x01, 0x00, 0x00, 0x00, // MajorVersion: 1
					0x00, 0x00, 0x00, 0x00, // MinorVersion: 0
					0xFE, 0x00, 0x00, 0x00, // TriggerReason: 254
				}
				// Add UUID bytes
				uuid := []byte{0x12, 0x34, 0x56, 0x78, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				response = append(response, uuid...)
				// Add Reserved bytes (64 bytes)
				reserved := make([]byte, 64)
				response = append(response, reserved...)
				copy(buffer, response)

				return uint32(len(response)), nil
			case 2:
				// Second call: Return APF_SERVICE_REQUEST
				response := []byte{
					0x05,                   // MessageType: 5 (APF_SERVICE_REQUEST)
					0x00, 0x00, 0x00, 0x12, // ServiceNameLength: 18
				}
				serviceName := []byte("pfwd@amt.intel.com")
				response = append(response, serviceName...)
				copy(buffer, response)

				return uint32(len(response)), nil
			case 3:
				// Third call: Return APF_GLOBAL_REQUEST for tcpip-forward (port 16992)
				response := []byte{
					0x50,                   // MessageType: 80 (APF_GLOBAL_REQUEST)
					0x00, 0x00, 0x00, 0x0D, // StringLength: 13
				}
				requestType := []byte("tcpip-forward")
				response = append(response, requestType...)
				response = append(response, []byte{
					0x01,                   // WantReply: 1
					0x00, 0x00, 0x00, 0x00, // AddressLength: 0
					0x42, 0x60, 0x00, 0x00, // Port: 16992
				}...)
				copy(buffer, response)

				return uint32(len(response)), nil
			case 4:
				// Fourth call: Return another APF_GLOBAL_REQUEST for tcpip-forward (port 623)
				response := []byte{
					0x50,                   // MessageType: 80 (APF_GLOBAL_REQUEST)
					0x00, 0x00, 0x00, 0x0D, // StringLength: 13
				}
				requestType := []byte("tcpip-forward")
				response = append(response, requestType...)
				response = append(response, []byte{
					0x01,                   // WantReply: 1
					0x00, 0x00, 0x00, 0x00, // AddressLength: 0
					0x6F, 0x02, 0x00, 0x00, // Port: 623
				}...)
				copy(buffer, response)

				return uint32(len(response)), nil
			default:
				// Subsequent calls: Return empty to complete the sequence
				return 0, errors.New("empty response from AMT")
			}
		},
	}

	command := pthi.Command{Heci: mockHECI}

	lme := &LMEConnection{
		Command: command,
		Session: &apf.Session{
			WaitGroup: &sync.WaitGroup{},
		},
	}

	// Start with APF_PROTOCOL_VERSION message
	var bin_buf bytes.Buffer

	protocolVersion := apf.ProtocolVersion(1, 0, 9)
	binary.Write(&bin_buf, binary.BigEndian, protocolVersion)

	err := lme.execute(bin_buf)
	assert.NoError(t, err)
	// Verify multiple iterations occurred (at least processing the messages)
	assert.GreaterOrEqual(t, callCount, 4, "Expected at least 4 calls to process the APF protocol sequence")
}

func TestLMEConnection_Execute_ThreadSafety(t *testing.T) {
	callCount := 0

	var mu sync.Mutex

	mockHECI := &MockHECI{
		InitFunc: func(useLME, useWD bool) error {
			return nil
		},
		SendFunc: func(buffer []byte, done *uint32) (uint32, error) {
			mu.Lock()

			callCount++

			mu.Unlock()

			return uint32(len(buffer)), nil
		},
		ReceiveFunc: func(buffer []byte, done *uint32) (uint32, error) {
			// Simulate some processing time
			time.Sleep(50 * time.Millisecond)

			return 0, errors.New("empty response from AMT")
		},
	}

	command := pthi.Command{Heci: mockHECI}

	lme := &LMEConnection{
		Command: command,
		Session: &apf.Session{
			WaitGroup: &sync.WaitGroup{},
		},
	}

	var bin_buf bytes.Buffer
	binary.Write(&bin_buf, binary.BigEndian, uint32(1))

	// Launch multiple concurrent execute calls
	numGoroutines := 5
	wg := &sync.WaitGroup{}
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			err := lme.execute(bin_buf)
			errChan <- err
		}()
	}

	wg.Wait()
	close(errChan)

	// All should complete without error
	for err := range errChan {
		assert.NoError(t, err)
	}

	// Should have exactly numGoroutines calls (serialized)
	mu.Lock()
	assert.Equal(t, numGoroutines, callCount)
	mu.Unlock()
}
