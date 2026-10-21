/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// closeCounter is a local management connection that only counts Close calls.
// An LME connection that is not closed keeps the MEI device open, and the
// next HECI call in the same process fails with "device busy".
type closeCounter struct {
	closes int
}

func (c *closeCounter) Initialize() error   { return nil }
func (c *closeCounter) Connect() error      { return nil }
func (c *closeCounter) Listen()             {}
func (c *closeCounter) Send(_ []byte) error { return nil }

func (c *closeCounter) Close() error {
	c.closes++

	return nil
}

func TestConnectToRPSFailureClosesLocalManagement(t *testing.T) {
	// The server refuses the WebSocket upgrade, so the RPS connection fails.
	refusing := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(refusing.Close)

	local := &closeCounter{}
	executor := Executor{
		server:          NewAMTActivationServer("ws"+strings.TrimPrefix(refusing.URL, "http"), ""),
		localManagement: local,
	}

	err := executor.connectToRPS(true)

	assert.Error(t, err)
	assert.Equal(t, 1, local.closes)
}

func TestConnectToRPSSuccessKeepsLocalManagementOpen(t *testing.T) {
	local := &closeCounter{}
	executor := Executor{server: NewAMTActivationServer(testUrl, ""), localManagement: local}

	require.NoError(t, executor.connectToRPS(true))
	t.Cleanup(func() { _ = executor.server.Close() })

	assert.Equal(t, 0, local.closes)
}

func TestMakeItSoClosesLocalManagement(t *testing.T) {
	tests := []struct {
		name    string
		request Message
		// closeRPS closes the RPS connection before the request is sent.
		closeRPS bool
		wantErr  string
	}{
		{
			name:     "when sending the request fails",
			closeRPS: true,
			wantErr:  "failed to send activation request",
		},
		{
			// The echo server returns the request, so RPS appears to report success.
			name:    "when RPS reports success",
			request: Message{Method: "success"},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			server := NewAMTActivationServer(testUrl, "")
			require.NoError(t, server.Connect(true))
			t.Cleanup(func() { _ = server.Close() })

			if tt.closeRPS {
				require.NoError(t, server.Close())
			}

			local := &closeCounter{}
			executor := &Executor{server: server, localManagement: local}

			err := executor.MakeItSo(tt.request)

			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}

			assert.Equal(t, 1, local.closes)
		})
	}
}

var errFakeMEI = errors.New("fake MEI device error")

// openTracker is an MEI device that opens but fails every read and write, so
// the APF handshake in LMEConnection.Initialize fails while the device is open.
type openTracker struct {
	open bool
}

func (d *openTracker) Init(_, _ bool) error {
	d.open = true

	return nil
}

func (d *openTracker) InitWithGUID(_ interface{}) error { return nil }
func (d *openTracker) InitHOTHAM() error                { return nil }
func (d *openTracker) GetBufferSize() uint32            { return 0 }

func (d *openTracker) SendMessage(_ []byte, _ *uint32) (int, error) {
	return 0, errFakeMEI
}

func (d *openTracker) ReceiveMessage(_ []byte, _ *uint32) (int, error) {
	return 0, errFakeMEI
}

func (d *openTracker) Close() { d.open = false }

func TestNewExecutorInitializeFailureClosesLME(t *testing.T) {
	if utils.DetectLMS(false) {
		t.Skip("LMS is listening on this machine, so NewExecutor uses LMS, not LME")
	}

	device := &openTracker{}
	original := newLMEConnection

	newLMEConnection = func(data chan []byte, errs chan error, wg *sync.WaitGroup) *lm.LMEConnection {
		lme := original(data, errs, wg)
		lme.Command = pthi.Command{Heci: device}

		return lme
	}

	t.Cleanup(func() { newLMEConnection = original })

	// Initialize fails before NewExecutor connects to RPS, so testUrl is never dialed.
	_, err := NewExecutor(ExecutorConfig{URL: testUrl})

	require.ErrorIs(t, err, errFakeMEI)
	assert.ErrorContains(t, err, "failed to initialize LME connection")
	assert.False(t, device.open, "NewExecutor left the MEI device open")
}
