/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// captureStdout returns what fn writes to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	oldStdout := os.Stdout
	os.Stdout = w

	defer func() { os.Stdout = oldStdout }()

	// Read concurrently so output larger than the pipe buffer cannot block fn.
	out := make(chan string)

	go func() {
		data, _ := io.ReadAll(r)
		out <- string(data)
	}()

	fn()

	require.NoError(t, w.Close())

	return <-out
}

func TestAmtInfoCmd_Run_SignalsElevationAfterPrinting(t *testing.T) {
	hostname, err := os.Hostname()
	require.NoError(t, err)

	tests := []struct {
		name     string
		elevated bool
		wantErr  error
	}{
		{name: "not elevated", wantErr: utils.IncorrectPermissions},
		{name: "elevated without HECI", elevated: true},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			origIsElevated := isElevated
			defer func() { isElevated = origIsElevated }()

			isElevated = func() bool { return tt.elevated }

			cmd := &AmtInfoCmd{Hostname: true}
			ctx := &Context{AMTCommand: mock.NewMockInterface(gomock.NewController(t))}

			var runErr error

			out := captureStdout(t, func() { runErr = cmd.Run(ctx) })

			if tt.wantErr != nil {
				require.ErrorIs(t, runErr, tt.wantErr)
			} else {
				require.NoError(t, runErr)
			}

			assert.Contains(t, out, hostname)
		})
	}
}

func TestAmtInfoCmd_Run_ClosesWSMANClient(t *testing.T) {
	tests := []struct {
		name string
		ctx  Context
	}{
		{name: "text output"},
		{name: "JSON output", ctx: Context{JsonOutput: true}},
		{name: "table output", ctx: Context{TableOutput: true}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			mockAMT := mock.NewMockInterface(ctrl)
			mockAMT.EXPECT().GetControlMode().Return(1, nil)

			mockWSMAN := mock.NewMockWSMANer(ctrl)
			mockWSMAN.EXPECT().GetHTTPProxyAccessPoints().Return(nil, nil)
			mockWSMAN.EXPECT().Close().Return(nil).Times(1)

			cmd := &AmtInfoCmd{AMTBaseCmd: AMTBaseCmd{HECIAvailable: true, WSMan: mockWSMAN}, Proxy: true}
			ctx := tt.ctx
			ctx.AMTCommand = mockAMT

			var err error

			captureStdout(t, func() { err = cmd.Run(&ctx) })

			require.NoError(t, err)
		})
	}
}

// expectFullRead lets mockAMT answer every HECI read a full (All) read makes.
func expectFullRead(mockAMT *mock.MockInterface) {
	mockAMT.EXPECT().GetVersionDataFromME(gomock.Any(), gomock.Any()).Return("16.1.25", nil).AnyTimes()
	mockAMT.EXPECT().GetUUID().Return("12345678-1234-1234-1234-123456789ABC", nil).AnyTimes()
	mockAMT.EXPECT().GetUPID().Return(nil, nil).AnyTimes()
	mockAMT.EXPECT().GetControlMode().Return(1, nil).AnyTimes()
	mockAMT.EXPECT().GetProvisioningState().Return(2, nil).AnyTimes()
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), nil).AnyTimes()
	mockAMT.EXPECT().GetDNSSuffix().Return("example.com", nil).AnyTimes()
	mockAMT.EXPECT().GetOSDNSSuffix().Return("os.example.com", nil).AnyTimes()
	mockAMT.EXPECT().GetLocalSystemAccount().Return(amt.LocalSystemAccount{}, errors.New("not available")).AnyTimes()
	mockAMT.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{}, nil).AnyTimes()
	mockAMT.EXPECT().GetLANInterfaceSettings(gomock.Any()).Return(amt.InterfaceSettings{}, nil).AnyTimes()
	mockAMT.EXPECT().GetCertificateHashes().Return([]amt.CertHashEntry{}, nil).AnyTimes()
}

func TestAmtInfoCmd_Collect_ReturnsResultWithoutPrinting(t *testing.T) {
	mockAMT := mock.NewMockInterface(gomock.NewController(t))
	mockAMT.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("16.1.25", nil)

	cmd := &AmtInfoCmd{AMTBaseCmd: AMTBaseCmd{HECIAvailable: true}, Ver: true}

	var (
		result *InfoResult
		err    error
	)

	out := captureStdout(t, func() { result, err = cmd.Collect(&Context{AMTCommand: mockAMT}) })

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "16.1.25", result.AMT)
	assert.Empty(t, out)
}

func TestAmtInfoCmd_Collect_SignalsElevationWithResult(t *testing.T) {
	tests := []struct {
		name          string
		heciAvailable bool
		elevated      bool
		wantErr       error
	}{
		{name: "HECI unavailable and not elevated", wantErr: utils.IncorrectPermissions},
		{name: "HECI unavailable but elevated", elevated: true},
		{name: "HECI available", heciAvailable: true, elevated: true},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			origIsElevated := isElevated
			defer func() { isElevated = origIsElevated }()

			isElevated = func() bool { return tt.elevated }

			cmd := &AmtInfoCmd{AMTBaseCmd: AMTBaseCmd{HECIAvailable: tt.heciAvailable}, Hostname: true}

			result, err := cmd.Collect(&Context{AMTCommand: mock.NewMockInterface(gomock.NewController(t))})

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			require.NotNil(t, result)
			require.NotNil(t, result.HECIAvailable)
			assert.Equal(t, tt.heciAvailable, *result.HECIAvailable)
			assert.NotEmpty(t, result.HostnameOS)
		})
	}
}

func TestAmtInfoCmd_Collect_ClosesWSMANClient(t *testing.T) {
	origSMBIOS := getSMBIOSSystemUUID
	defer func() { getSMBIOSSystemUUID = origSMBIOS }()

	// Without a UUID the sync fails before it sends any request.
	getSMBIOSSystemUUID = func() (string, error) { return "", errors.New("SMBIOS unavailable") }

	readProxy := func(mockAMT *mock.MockInterface, mockWSMAN *mock.MockWSMANer) {
		mockAMT.EXPECT().GetControlMode().Return(1, nil)
		mockWSMAN.EXPECT().GetHTTPProxyAccessPoints().Return(nil, nil)
	}

	tests := []struct {
		name     string
		cmd      AmtInfoCmd
		elevated bool
		expect   func(*mock.MockInterface, *mock.MockWSMANer)
		closeErr error
		wantErr  string
		// wantPermErr: the sync needed elevation, so the result comes back with
		// the sync's IncorrectPermissions error instead of a failure.
		wantPermErr bool
	}{
		{
			name:   "after a read",
			cmd:    AmtInfoCmd{AMTBaseCmd: AMTBaseCmd{HECIAvailable: true}, Proxy: true},
			expect: readProxy,
		},
		{
			name:     "after a failed sync",
			cmd:      AmtInfoCmd{Sync: true, URL: "https://console.example.com/api/v1/devices"},
			elevated: true,
			expect: func(mockAMT *mock.MockInterface, _ *mock.MockWSMANer) {
				mockAMT.EXPECT().GetUPID().Return(nil, nil).AnyTimes()
				mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil).AnyTimes()
			},
			wantErr: "device sync failed: cannot sync: device UUID unavailable",
		},
		{
			name: "after a sync that needs elevation",
			cmd:  AmtInfoCmd{Sync: true, URL: "https://console.example.com/api/v1/devices"},
			expect: func(mockAMT *mock.MockInterface, _ *mock.MockWSMANer) {
				mockAMT.EXPECT().GetUPID().Return(nil, nil).AnyTimes()
				mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil).AnyTimes()
			},
			wantPermErr: true,
		},
		{
			name:     "ignoring a close failure",
			cmd:      AmtInfoCmd{AMTBaseCmd: AMTBaseCmd{HECIAvailable: true}, Proxy: true},
			expect:   readProxy,
			closeErr: errors.New("close failed"),
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			origIsElevated := isElevated
			defer func() { isElevated = origIsElevated }()

			isElevated = func() bool { return tt.elevated }

			ctrl := gomock.NewController(t)
			mockAMT := mock.NewMockInterface(ctrl)
			mockWSMAN := mock.NewMockWSMANer(ctrl)

			tt.expect(mockAMT, mockWSMAN)
			mockWSMAN.EXPECT().Close().Return(tt.closeErr).Times(1)

			// The command's client stands in for the one the read opens lazily:
			// either way the service holds it.
			cmd := tt.cmd
			cmd.WSMan = mockWSMAN

			result, err := cmd.Collect(&Context{AMTCommand: mockAMT})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, result)

				return
			}

			if tt.wantPermErr {
				var customErr utils.CustomError

				require.ErrorAs(t, err, &customErr)
				assert.Equal(t, utils.IncorrectPermissions.Code, customErr.Code)
				assert.Equal(t, ErrSyncUUIDUnavailable.Error(), customErr.Details)
				require.NotNil(t, result)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.NotNil(t, result.ProxyAccessPoints)
		})
	}
}

func TestAmtInfoCmd_Collect_SyncsAFullRead(t *testing.T) {
	mockAMT := mock.NewMockInterface(gomock.NewController(t))
	expectFullRead(mockAMT)

	var patches int

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)

		if r.Method == http.MethodPatch {
			patches++
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Only Ver is selected, but a sync reads everything, as Run's does.
	cmd := &AmtInfoCmd{AMTBaseCmd: AMTBaseCmd{HECIAvailable: true}, Ver: true, Sync: true, URL: server.URL + "/api/v1/devices"}

	var (
		result *InfoResult
		err    error
	)

	out := captureStdout(t, func() { result, err = cmd.Collect(&Context{AMTCommand: mockAMT, SkipCertCheck: true}) })

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, patches)
	assert.NotNil(t, result.CertificateHashes, "certificate hashes are only read for All")
	assert.NotEmpty(t, result.HostnameOS)
	assert.Empty(t, out)
}

func TestInfoService_closeWSMAN(t *testing.T) {
	mockWSMAN := mock.NewMockWSMANer(gomock.NewController(t))
	mockWSMAN.EXPECT().Close().Return(nil).Times(1)

	service := NewInfoService(nil, WithWSMANClient(mockWSMAN))

	service.closeWSMAN()
	service.closeWSMAN() // the client is released, so there is nothing left to close

	assert.Nil(t, service.wsman)
}

func TestInfoService_closeWSMAN_WithoutClient(t *testing.T) {
	assert.NotPanics(t, NewInfoService(nil).closeWSMAN)
}
