/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
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
	sendBytesWritten int
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
func (c *MockHECICommands) InitHOTHAM() error             { return initError }
func (c *MockHECICommands) GetBufferSize() uint32         { return bufferSize } // MaxMessageLength
func (c *MockHECICommands) SendMessage(buffer []byte, done *uint32) (bytesWritten int, err error) {
	return sendBytesWritten, sendError
}

func (c *MockHECICommands) ReceiveMessage(buffer []byte, done *uint32) (bytesRead int, err error) {
	for i := 0; i < len(message) && i < len(buffer); i++ {
		buffer[i] = message[i]
	}

	return len(message), nil
}

// queuedHECIMock is an instance-scoped heci.Interface fake used by channel-lifecycle
// tests. Unlike MockHECICommands, it doesn't share state across goroutines or tests:
// ReceiveMessage pulls one frame per call from queue, and SendMessage reports the
// payload length back so pthi.Command.Send doesn't see a byteswritten mismatch.
type queuedHECIMock struct {
	queue chan []byte
}

func newQueuedHECIMock(buffer int) *queuedHECIMock {
	return &queuedHECIMock{queue: make(chan []byte, buffer)}
}

func (m *queuedHECIMock) Init(useLME, useWD bool) error       { return nil }
func (m *queuedHECIMock) InitHOTHAM() error                   { return nil }
func (m *queuedHECIMock) InitWithGUID(guid interface{}) error { return nil }
func (m *queuedHECIMock) GetBufferSize() uint32               { return 5120 }
func (m *queuedHECIMock) SendMessage(buffer []byte, done *uint32) (int, error) {
	return len(buffer), nil
}

func (m *queuedHECIMock) ReceiveMessage(buffer []byte, done *uint32) (int, error) {
	frame, ok := <-m.queue
	if !ok {
		return 0, nil
	}

	return copy(buffer, frame), nil
}

func (m *queuedHECIMock) Close()                                {}
func (c *MockHECICommands) InitWithGUID(guid interface{}) error { return initError }
func (c *MockHECICommands) Close()                              {}

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

func Test_apfInitHandler_allExpectedSeen_MatchingPairsOnly(t *testing.T) {
	h := &apfInitHandler{seenPorts: map[uint32]bool{}}

	assert.False(t, h.allExpectedSeen())

	h.seenPorts[16992] = true
	h.seenPorts[664] = true
	assert.False(t, h.allExpectedSeen(), "mixed management/redirection pair must not be treated as ready")

	h.seenPorts[623] = true
	assert.True(t, h.allExpectedSeen(), "non-TLS pair should be ready")

	h = &apfInitHandler{seenPorts: map[uint32]bool{}}
	h.seenPorts[16993] = true
	h.seenPorts[664] = true
	assert.True(t, h.allExpectedSeen(), "TLS-enforced pair should be ready")
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

// newLMEWithQueuedHECI builds an LMEConnection wired to an instance-scoped HECI
// mock so channel-lifecycle tests don't contend with other tests' goroutines on
// shared package state.
func newLMEWithQueuedHECI(handshakeConfirmed bool) (*LMEConnection, *queuedHECIMock) {
	mock := newQueuedHECIMock(4)

	return &LMEConnection{
		Command: pthi.Command{Heci: mock},
		Session: &apf.Session{
			DataBuffer:         make(chan []byte, 1),
			ErrorBuffer:        make(chan error, 1),
			Status:             make(chan bool, 1),
			WaitGroup:          &sync.WaitGroup{},
			HandshakeConfirmed: handshakeConfirmed,
			RecipientChannel:   1,
		},
		ourChannel: 1,
	}, mock
}

// Test_Listen_CloseExitsWhenHandshakeConfirmed verifies a CHANNEL_CLOSE received
// after the APF handshake terminates Listen. This is the normal teardown path.
func Test_Listen_CloseExitsWhenHandshakeConfirmed(t *testing.T) {
	lme, mock := newLMEWithQueuedHECI(true)

	done := make(chan struct{})

	go func() {
		lme.Listen()
		close(done)
	}()

	mock.queue <- apf.BuildChannelCloseBytes(1)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not exit after CHANNEL_CLOSE with HandshakeConfirmed=true")
	}

	close(mock.queue)
}

// Test_Listen_StaleChannelCloseIgnoredWhenConfirmed verifies that a CHANNEL_CLOSE
// for a channel other than our active one (e.g. a stale RecipientChannel 0 close
// replayed by AMT after an MEI reinit) does NOT terminate Listen even when the
// handshake is confirmed. Our channel is still live and about to deliver its
// response; exiting here would drop it and force a needless re-handshake. An
// OPEN_FAILURE is fed afterwards as an unambiguous exit signal to prove Listen
// kept running past the stale close.
func Test_Listen_StaleChannelCloseIgnoredWhenConfirmed(t *testing.T) {
	lme, mock := newLMEWithQueuedHECI(true)

	// ProcessChannelOpenFailure calls Done() on the WaitGroup, so pre-add to
	// balance the counter (mirrors what Connect() does in production).
	lme.Session.WaitGroup.Add(1)

	done := make(chan struct{})

	go func() {
		lme.Listen()
		close(done)
	}()

	// Stale CLOSE for channel 0 while our active channel is 1. Listen must NOT exit.
	mock.queue <- apf.BuildChannelCloseBytes(0)

	select {
	case <-done:
		t.Fatal("Listen exited on stale CHANNEL_CLOSE for a non-active channel")
	case <-time.After(100 * time.Millisecond):
	}

	// OPEN_FAILURE: 17 bytes big-endian — type(1) + recipient(4) + reason(4) + reserved(4) + reserved2(4).
	openFailure := make([]byte, 17)

	openFailure[0] = apf.APF_CHANNEL_OPEN_FAILURE
	mock.queue <- openFailure

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not exit after OPEN_FAILURE following the ignored stale close")
	}

	close(mock.queue)
}

// Test_Listen_StaleCloseIgnoredUntilOpenFailure verifies that a CHANNEL_CLOSE
// arriving before OPEN_CONFIRMATION (i.e., a stale close from a previous channel)
// does NOT terminate Listen. This is the bug the HandshakeConfirmed gate fixed:
// exiting on a stale CLOSE would orphan the current transaction's reader.
// OPEN_FAILURE is then used as an unambiguous exit signal to confirm Listen is
// still running after the ignored CLOSE.
func Test_Listen_StaleCloseIgnoredUntilOpenFailure(t *testing.T) {
	lme, mock := newLMEWithQueuedHECI(false)

	// ProcessChannelOpenFailure calls Done() on the WaitGroup, so pre-add to
	// balance the counter (mirrors what Connect() does in production).
	lme.Session.WaitGroup.Add(1)

	done := make(chan struct{})

	go func() {
		lme.Listen()
		close(done)
	}()

	// Feed a stale CLOSE first. Listen must NOT exit.
	mock.queue <- apf.BuildChannelCloseBytes(1)

	select {
	case <-done:
		t.Fatal("Listen exited on CHANNEL_CLOSE while HandshakeConfirmed=false (stale CLOSE should be ignored)")
	case <-time.After(100 * time.Millisecond):
	}

	// OPEN_FAILURE: 17 bytes big-endian — type(1) + recipient(4) + reason(4) + reserved(4) + reserved2(4).
	openFailure := make([]byte, 17)
	openFailure[0] = apf.APF_CHANNEL_OPEN_FAILURE
	openFailure[4] = 0x01 // recipient channel = 1

	mock.queue <- openFailure

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not exit after CHANNEL_OPEN_FAILURE")
	}

	close(mock.queue)
}
