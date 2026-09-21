/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/stretchr/testify/assert"
)

type fakeLocalManagement struct {
	connectErr  error
	initialized bool
	closed      bool
	port        uint32
}

func (fake *fakeLocalManagement) Initialize() error {
	fake.initialized = true

	return nil
}

func (fake *fakeLocalManagement) Connect() error {
	return fake.connectErr
}

func (fake *fakeLocalManagement) Listen() {}

func (fake *fakeLocalManagement) Send([]byte) error {
	return nil
}

func (fake *fakeLocalManagement) Close() error {
	fake.closed = true

	return nil
}

func (fake *fakeLocalManagement) SetPort(port uint32) {
	fake.port = port
}

func assertInitialPayloadLMSAvailability(t *testing.T, message Message, expected bool) {
	t.Helper()

	data, err := base64.StdEncoding.DecodeString(message.Payload)
	if err != nil {
		t.Fatal(err)
	}

	var payload MessagePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(payload.LMSAvailable, expected) {
		t.Fatalf("expected lmsAvailable=%v, got %v", expected, payload.LMSAvailable)
	}
}

func TestNewExecutorReportsLMSAvailable(t *testing.T) {
	lms := &fakeLocalManagement{}
	originalLMSFactory := newLMSConnection
	originalLMEFactory := newLMEConnection
	newLMSConnection = func(string, string, bool, chan []byte, chan error, int, bool) lm.LocalMananger {
		return lms
	}
	newLMEConnection = func(chan []byte, chan error, *sync.WaitGroup) lmeConnection {
		t.Fatal("LME fallback should not be used")

		return nil
	}

	t.Cleanup(func() {
		newLMSConnection = originalLMSFactory
		newLMEConnection = originalLMEFactory
	})

	executor, err := NewExecutor(ExecutorConfig{URL: testUrl, SkipCertCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	defer executor.server.Close()

	if !executor.lmsAvailable {
		t.Fatal("expected LMS to be available")
	}

	if !lms.closed {
		t.Fatal("expected LMS probe connection to close")
	}

	message, err := (Payload{AMT: MockAMT{}, LMSAvailable: executor.lmsAvailable}).CreateMessageRequest(*testReq)
	if err != nil {
		t.Fatal(err)
	}

	assertInitialPayloadLMSAvailability(t, message, true)
}

func TestNewExecutorReportsLMEFallback(t *testing.T) {
	lms := &fakeLocalManagement{connectErr: errors.New("LMS unavailable")}
	lme := &fakeLocalManagement{}
	originalLMSFactory := newLMSConnection
	originalLMEFactory := newLMEConnection
	newLMSConnection = func(string, string, bool, chan []byte, chan error, int, bool) lm.LocalMananger {
		return lms
	}
	newLMEConnection = func(chan []byte, chan error, *sync.WaitGroup) lmeConnection {
		return lme
	}

	t.Cleanup(func() {
		newLMSConnection = originalLMSFactory
		newLMEConnection = originalLMEFactory
	})

	executor, err := NewExecutor(ExecutorConfig{URL: testUrl, SkipCertCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	defer executor.server.Close()
	defer executor.localManagement.Close()

	if executor.lmsAvailable {
		t.Fatal("expected LMS to be unavailable")
	}

	if !executor.isLME {
		t.Fatal("expected LME fallback")
	}

	if !lme.initialized {
		t.Fatal("expected LME to be initialized")
	}

	message, err := (Payload{AMT: MockAMT{}, LMSAvailable: executor.lmsAvailable}).CreateMessageRequest(*testReq)
	if err != nil {
		t.Fatal(err)
	}

	assertInitialPayloadLMSAvailability(t, message, false)
}

// TestClassifyLMSError pins the relay's error triage. The regression this guards
// against: a read timeout with no bytes (lm.ErrLMSReadTimeoutNoData) is a benign
// quiet round — AMT acknowledging a WSMAN request such as the activating Setup
// without an immediate reply — and must NOT fail the activation on the plain
// (non-TLS-tunnel) RPS relay. Genuine LMS errors must still classify as fatal.
func TestClassifyLMSError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want lmsErrorClass
	}{
		{"heci poll timeout", heci.ErrReadTimeout, lmsErrorPoll},
		{"wrapped heci poll timeout", fmt.Errorf("polling: %w", heci.ErrReadTimeout), lmsErrorPoll},
		{"quiet round no data", lm.ErrLMSReadTimeoutNoData, lmsErrorQuietRound},
		{"wrapped quiet round no data", fmt.Errorf("listen: %w", lm.ErrLMSReadTimeoutNoData), lmsErrorQuietRound},
		{"genuine lms error is fatal", errors.New("connection reset by peer"), lmsErrorFatal},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, classifyLMSError(tt.err))
		})
	}
}
