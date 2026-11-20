/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errBadFileDescriptor = errors.New("bad file descriptor")

// fakeLocalManagement mimics the handle semantics of lm.LMEConnection: Close
// closes the device handle, and Connect on a closed handle fails.
type fakeLocalManagement struct {
	data     chan []byte
	response []byte
	closed   bool
	connects int
	closes   int
}

func (f *fakeLocalManagement) Initialize() error { return nil }

func (f *fakeLocalManagement) Connect() error {
	if f.closed {
		return errBadFileDescriptor
	}

	f.connects++

	return nil
}

func (f *fakeLocalManagement) Listen() {}

func (f *fakeLocalManagement) Send(_ []byte) error {
	if f.closed {
		return errBadFileDescriptor
	}

	go func() { f.data <- f.response }()

	return nil
}

func (f *fakeLocalManagement) Close() error {
	f.closed = true
	f.closes++

	return nil
}

func newTestExecutor(t *testing.T, isLME bool, response []byte) (*Executor, *fakeLocalManagement) {
	t.Helper()

	server := NewAMTActivationServer(testFlags)
	require.NoError(t, server.Connect(true))
	t.Cleanup(func() { server.Close() })

	data := make(chan []byte)
	fake := &fakeLocalManagement{data: data, response: response}

	return &Executor{
		server:          server,
		localManagement: fake,
		isLME:           isLME,
		data:            data,
		errors:          make(chan error),
		waitGroup:       &sync.WaitGroup{},
	}, fake
}

func rpsMessage(t *testing.T, payload string) []byte {
	t.Helper()

	msg, err := json.Marshal(Message{Payload: base64.StdEncoding.EncodeToString([]byte(payload))})
	require.NoError(t, err)

	return msg
}

func TestHandleDataFromRPS_LMEKeepsHandleOpenBetweenMessages(t *testing.T) {
	for _, response := range [][]byte{[]byte("HTTP/1.1 200 OK"), {}} {
		e, fake := newTestExecutor(t, true, response)

		for i := 0; i < 3; i++ {
			assert.False(t, e.HandleDataFromRPS(rpsMessage(t, "POST /wsman HTTP/1.1")), "message %d", i)
		}

		assert.Equal(t, 3, fake.connects)
		assert.Equal(t, 0, fake.closes, "LME must not close /dev/mei0 between messages")
	}
}

func TestHandleDataFromRPS_LMSClosesConnectionAfterEachMessage(t *testing.T) {
	e, fake := newTestExecutor(t, false, []byte("HTTP/1.1 200 OK"))

	// LMS opens a fresh TCP connection per message, so reset the fake handle state.
	for i := 0; i < 3; i++ {
		fake.closed = false

		assert.False(t, e.HandleDataFromRPS(rpsMessage(t, "POST /wsman HTTP/1.1")), "message %d", i)
	}

	assert.Equal(t, 3, fake.connects)
	assert.Equal(t, 3, fake.closes)
}
