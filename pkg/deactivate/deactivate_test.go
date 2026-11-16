/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package deactivate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var (
	errUnexpectedPrompt = errors.New("unexpected password prompt")
	errRunFailed        = errors.New("run failed")
	errCloseFailed      = errors.New("close failed")
	errCheckFailed      = errors.New("check failed")
	errValidateFailed   = errors.New("validate failed")
)

const (
	authEndpoint    = "https://console.example.com/api/v1/authorize"
	devicesEndpoint = "https://console.example.com/api/v1/devices"
	consoleURL      = "https://console.example.com"
	rpsURL          = "wss://rps.example.com/activate"
	deviceUUID      = "4c4c4544-0000-1000-8000-000000000000"
)

// noPrompt fails every password prompt so a test can never block on stdin.
type noPrompt struct{}

func (noPrompt) ReadPassword() (string, error) { return "", errUnexpectedPrompt }

func (noPrompt) ReadPasswordWithConfirmation(_, _ string) (string, error) {
	return "", errUnexpectedPrompt
}

// amtReachable is set by TestMain when this process is elevated and HECI is
// present. A call that passes validation would then get past AMT access and
// really deactivate this device, so requireReachedAMT skips it.
var amtReachable bool

func TestMain(m *testing.M) {
	utils.PR = noPrompt{}
	amtReachable = utils.IsElevated() && !heciAbsent(probeControlMode())

	os.Exit(m.Run())
}

// probeControlMode reads the AMT control mode, a read-only HECI query, and
// closes the HECI connection again.
func probeControlMode() error {
	amtCommand := amt.NewAMTCommand()
	defer amtCommand.Close()

	_, err := amtCommand.GetControlMode()

	return err
}

// heciAbsent reports whether a probe error shows that the process cannot use
// a HECI device on this machine. Any other failure, such as a device another
// process holds, can clear while a test runs, so HECI counts as present.
func heciAbsent(probeErr error) bool {
	return errors.Is(probeErr, heci.ErrDeviceNotFound) ||
		errors.Is(probeErr, heci.ErrUnsupportedDevice) ||
		errors.Is(probeErr, heci.ErrPermissionDenied)
}

// requireReachedAMT runs call and asserts that validation passed and the call
// failed only on AMT access. When AMT is reachable it skips the test without
// running call, which would deactivate this device.
func requireReachedAMT(t *testing.T, call func() error) {
	t.Helper()

	if amtReachable {
		t.Skip("skipped: this process is elevated and AMT is reachable over HECI, so the call would deactivate this device")
	}

	err := call()
	if !failedOnAMTAccess(err) {
		t.Fatalf("expected validation to pass and AMT access to fail, got: %v", err)
	}
}

// failedOnAMTAccess reports whether err is one of the errors the command's
// AfterApply returns when it cannot use AMT: the process is not elevated, no
// HECI driver or device was found, or the MEI device has no AMT client
// (non-vPro hardware, where heciAbsent lets these tests run).
func failedOnAMTAccess(err error) bool {
	return errors.Is(err, utils.IncorrectPermissions) ||
		errors.Is(err, utils.HECIDriverNotDetected) ||
		errors.Is(err, utils.AmtNotDetected)
}

func TestHECIAbsent(t *testing.T) {
	tests := []struct {
		name     string
		probeErr error
		want     bool
	}{
		{"AMT answered", nil, false},
		{"device held by another process", fmt.Errorf("connect: %w", syscall.EBUSY), false},
		{"no MEI device or driver", fmt.Errorf("%w: %w", heci.ErrDeviceNotFound, fs.ErrNotExist), true},
		{"no AMT client on the MEI device", heci.ErrUnsupportedDevice, true},
		{"no access to the MEI device", heci.ErrPermissionDenied, true},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, heciAbsent(tt.probeErr))
		})
	}
}

func TestFailedOnAMTAccess(t *testing.T) {
	// The wrapped errors are the ones AfterApply builds from a failed HECI probe.
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"not elevated", utils.IncorrectPermissions, true},
		{"no access to the MEI device", fmt.Errorf("%w: %w", utils.IncorrectPermissions, heci.ErrPermissionDenied), true},
		{"no HECI on this architecture", utils.HECIDriverNotDetected, true},
		{"no MEI device or driver", fmt.Errorf("%w: %w", utils.HECIDriverNotDetected, heci.ErrDeviceNotFound), true},
		{"no AMT client on the MEI device", fmt.Errorf("%w: %w", utils.AmtNotDetected, heci.ErrUnsupportedDevice), true},
		{"call succeeded", nil, false},
		{"validation failed", errRelativeAuthEndpoint, false},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, failedOnAMTAccess(tt.err))
		})
	}
}

func TestRequireReachedAMT_SkipsWithoutCallingWhenAMTIsReachable(t *testing.T) {
	reachable := amtReachable
	amtReachable = true

	t.Cleanup(func() { amtReachable = reachable })

	called := false

	var inner *testing.T

	t.Run("reach AMT", func(t *testing.T) {
		inner = t

		requireReachedAMT(t, func() error {
			called = true

			return nil
		})
	})

	assert.True(t, inner.Skipped())
	assert.False(t, called)
}

func TestValidOptionsReachAMT(t *testing.T) {
	tests := []struct {
		name string
		call func() error
	}{
		{"Run defaults", func() error { return Run(Options{}) }},
		{"Run partial unprovision", func() error {
			return Run(Options{AMTPassword: "P@ssw0rd", PartialUnprovision: true})
		}},
		{"Run console cleanup with credentials", func() error {
			return Run(Options{AuthEndpoint: authEndpoint, AuthUsername: "user", AuthPassword: "pass"})
		}},
		{"Run console cleanup with token", func() error {
			return Run(Options{AuthToken: "token", DevicesEndpoint: devicesEndpoint})
		}},
		{"Remote", func() error { return Remote(RemoteOptions{URL: rpsURL}) }},
		{"Remote with upper-case ws scheme and every option", func() error {
			return Remote(RemoteOptions{
				URL: "WS://rps.example.com/activate", AMTPassword: "P@ssw0rd", Force: true, TLSTunnel: true,
				TenantID: "tenant-1", SkipCertCheck: true, SkipAMTCertCheck: true,
			})
		}},
		{"Console with token", func() error { return Console(ConsoleOptions{URL: consoleURL, AuthToken: "token"}) }},
		{"Console with credentials and an auth endpoint relative to the URL", func() error {
			return Console(ConsoleOptions{
				URL: "HTTP://console.example.com", AuthUsername: "user", AuthPassword: "pass",
				AuthEndpoint: "/api/v1/authorize",
			})
		}},
		{"Console with every option", func() error {
			return Console(ConsoleOptions{
				URL: consoleURL, AMTPassword: "P@ssw0rd", UUID: deviceUUID, SkipAMTCertCheck: true,
				SkipCertCheck: true, TenantID: "tenant-1", AuthToken: "token",
				AuthEndpoint: authEndpoint, DevicesEndpoint: devicesEndpoint,
			})
		}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			requireReachedAMT(t, tt.call)
		})
	}
}

func TestInvalidOptionsRejectedBeforeAMTAccess(t *testing.T) {
	tests := []struct {
		name    string
		call    func() error
		wantErr string
	}{
		{
			name:    "Run with relative devices endpoint",
			call:    func() error { return Run(Options{DevicesEndpoint: "console.example.com/api/v1/devices"}) },
			wantErr: "--devices-endpoint must be an absolute HTTP(S) URL",
		},
		{
			name:    "Run with username but no password",
			call:    func() error { return Run(Options{AuthUsername: "user"}) },
			wantErr: "--auth-username requires --auth-password",
		},
		{
			name:    "Run with password but no username",
			call:    func() error { return Run(Options{AuthPassword: "pass"}) },
			wantErr: "--auth-password requires --auth-username",
		},
		{
			name:    "Run with auth endpoint but no credentials",
			call:    func() error { return Run(Options{AuthEndpoint: authEndpoint}) },
			wantErr: "--auth-endpoint requires --auth-token",
		},
		{
			name: "Run with relative auth endpoint",
			call: func() error {
				return Run(Options{AuthEndpoint: "/api/v1/authorize", AuthUsername: "user", AuthPassword: "pass"})
			},
			wantErr: "AuthEndpoint must be an absolute HTTP(S) URL",
		},
		{
			name:    "Run checks the auth flags before the relative auth endpoint",
			call:    func() error { return Run(Options{AuthEndpoint: "/api/v1/authorize"}) },
			wantErr: "--auth-endpoint requires --auth-token",
		},
		{
			name:    "Remote without URL",
			call:    func() error { return Remote(RemoteOptions{}) },
			wantErr: "RPS server URL is required",
		},
		{
			name:    "Remote with HTTPS URL",
			call:    func() error { return Remote(RemoteOptions{URL: consoleURL}) },
			wantErr: "unsupported url scheme: " + consoleURL + "; use Console for an http(s) URL",
		},
		{
			name:    "Remote with another scheme",
			call:    func() error { return Remote(RemoteOptions{URL: "ftp://rps.example.com"}) },
			wantErr: "unsupported url scheme: ftp://rps.example.com",
		},
		{
			name:    "Console without URL",
			call:    func() error { return Console(ConsoleOptions{AuthToken: "token"}) },
			wantErr: "Console URL is required",
		},
		{
			name:    "Console with WebSocket URL",
			call:    func() error { return Console(ConsoleOptions{URL: rpsURL, AuthToken: "token"}) },
			wantErr: "unsupported url scheme: " + rpsURL + "; use Remote for a ws(s) URL",
		},
		{
			name:    "Console with another scheme",
			call:    func() error { return Console(ConsoleOptions{URL: "ftp://console.example.com", AuthToken: "token"}) },
			wantErr: "unsupported url scheme: ftp://console.example.com",
		},
		{
			name:    "Console with URL without host",
			call:    func() error { return Console(ConsoleOptions{URL: "https://", AuthToken: "token"}) },
			wantErr: "URL must be an absolute HTTP(S) URL",
		},
		{
			name:    "Console with unparsable URL",
			call:    func() error { return Console(ConsoleOptions{URL: "https://[::1", AuthToken: "token"}) },
			wantErr: "URL must be an absolute HTTP(S) URL",
		},
		{
			name:    "Console without credentials",
			call:    func() error { return Console(ConsoleOptions{URL: consoleURL}) },
			wantErr: "authentication required: provide --auth-token or --auth-username and --auth-password",
		},
		{
			name:    "Console with blank token",
			call:    func() error { return Console(ConsoleOptions{URL: consoleURL, AuthToken: "  "}) },
			wantErr: "authentication required: provide --auth-token or --auth-username and --auth-password",
		},
		{
			name:    "Console with username but no password",
			call:    func() error { return Console(ConsoleOptions{URL: consoleURL, AuthUsername: "user"}) },
			wantErr: "--auth-username requires --auth-password",
		},
		{
			name: "Console with relative devices endpoint",
			call: func() error {
				return Console(ConsoleOptions{URL: consoleURL, AuthToken: "token", DevicesEndpoint: "/api/v1/devices"})
			},
			wantErr: "--devices-endpoint must be an absolute HTTP(S) URL",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorContains(t, tt.call(), tt.wantErr)
		})
	}
}

func TestNewCommand_MapsOptions(t *testing.T) {
	cmd, ctx := newCommand(Options{
		AMTPassword:        "amt-pass",
		PartialUnprovision: true,
		SkipAMTCertCheck:   true,
		UUID:               deviceUUID,
		SkipCertCheck:      true,
		TenantID:           "tenant-1",
		AuthToken:          "token",
		AuthUsername:       "user",
		AuthPassword:       "pass",
		AuthEndpoint:       authEndpoint,
		DevicesEndpoint:    devicesEndpoint,
	})

	assert.Equal(t, &commands.DeactivateCmd{
		Local:              true,
		PartialUnprovision: true,
		UUID:               deviceUUID,
	}, cmd)
	assert.Equal(t, &commands.Context{
		AMTPassword:      "amt-pass",
		SkipAMTCertCheck: true,
		SkipCertCheck:    true,
		TenantID:         "tenant-1",
		ServerAuthFlags: commands.ServerAuthFlags{
			AuthToken:       "token",
			AuthUsername:    "user",
			AuthPassword:    "pass",
			AuthEndpoint:    authEndpoint,
			DevicesEndpoint: devicesEndpoint,
		},
	}, ctx)
}

func TestNewRemoteCommand_MapsOptions(t *testing.T) {
	cmd, ctx := newRemoteCommand(RemoteOptions{
		URL:              rpsURL,
		AMTPassword:      "amt-pass",
		Force:            true,
		TLSTunnel:        true,
		TenantID:         "tenant-1",
		SkipCertCheck:    true,
		SkipAMTCertCheck: true,
	})

	assert.Equal(t, &commands.DeactivateCmd{
		URL:       rpsURL,
		Force:     true,
		TLSTunnel: true,
	}, cmd)
	assert.Equal(t, &commands.Context{
		AMTPassword:      "amt-pass",
		SkipAMTCertCheck: true,
		SkipCertCheck:    true,
		TenantID:         "tenant-1",
	}, ctx)
}

func TestNewConsoleCommand_MapsOptions(t *testing.T) {
	cmd, ctx := newConsoleCommand(ConsoleOptions{
		URL:              consoleURL,
		AMTPassword:      "amt-pass",
		UUID:             deviceUUID,
		SkipAMTCertCheck: true,
		SkipCertCheck:    true,
		TenantID:         "tenant-1",
		AuthToken:        "token",
		AuthUsername:     "user",
		AuthPassword:     "pass",
		AuthEndpoint:     "/api/v1/authorize",
		DevicesEndpoint:  devicesEndpoint,
	})

	assert.Equal(t, &commands.DeactivateCmd{
		URL:  consoleURL,
		UUID: deviceUUID,
	}, cmd)
	assert.Equal(t, &commands.Context{
		AMTPassword:      "amt-pass",
		SkipAMTCertCheck: true,
		SkipCertCheck:    true,
		TenantID:         "tenant-1",
		ServerAuthFlags: commands.ServerAuthFlags{
			AuthToken:       "token",
			AuthUsername:    "user",
			AuthPassword:    "pass",
			AuthEndpoint:    "/api/v1/authorize",
			DevicesEndpoint: devicesEndpoint,
		},
	}, ctx)
}

// fakeCmd stands in for the deactivate command. It records the hooks run
// calls, and Run opens the client, as EnsureWSMAN does.
type fakeCmd struct {
	client      interfaces.WSMANer
	validateErr error
	runErr      error
	wsman       interfaces.WSMANer
	calls       []string
}

func (f *fakeCmd) Validate() error {
	f.calls = append(f.calls, "Validate")

	return f.validateErr
}

func (f *fakeCmd) AfterApply(amt.Interface) error {
	f.calls = append(f.calls, "AfterApply")

	return nil
}

func (f *fakeCmd) GetWSManClient() interfaces.WSMANer { return f.wsman }

func (f *fakeCmd) Run(*commands.Context) error {
	f.calls = append(f.calls, "Run")
	f.wsman = f.client

	return f.runErr
}

func TestRunClosesWSMANClient(t *testing.T) {
	tests := []struct {
		name     string
		runErr   error
		closeErr error
	}{
		{name: "after a successful run"},
		{name: "after a failed run", runErr: errRunFailed},
		{name: "ignoring a close failure", closeErr: errCloseFailed},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			client := mock.NewMockWSMANer(gomock.NewController(t))
			client.EXPECT().Close().Return(tt.closeErr).Times(1)

			cmd := &fakeCmd{client: client, runErr: tt.runErr}
			err := run(cmd, &commands.Context{})

			assert.Equal(t, tt.runErr, err)
			assert.Equal(t, []string{"Validate", "AfterApply", "Run"}, cmd.calls)
		})
	}
}

func TestRunWithoutWSMANClient(t *testing.T) {
	assert.NoError(t, run(&fakeCmd{}, &commands.Context{}))
}

func TestRunStopsAtTheFirstFailedCheck(t *testing.T) {
	invalidAuth := &commands.Context{ServerAuthFlags: commands.ServerAuthFlags{AuthUsername: "user"}}
	failing := func() error { return errCheckFailed }
	passing := func() error { return nil }

	tests := []struct {
		name      string
		ctx       *commands.Context
		cmd       *fakeCmd
		checks    []func() error
		wantErr   string
		wantCalls []string
	}{
		{
			name: "auth flags before the checks", ctx: invalidAuth, cmd: &fakeCmd{},
			checks: []func() error{failing}, wantErr: "--auth-username requires --auth-password",
		},
		{
			name: "checks before the command's Validate", ctx: &commands.Context{}, cmd: &fakeCmd{},
			checks: []func() error{passing, failing}, wantErr: errCheckFailed.Error(),
		},
		{
			name: "the command's Validate before AMT access", ctx: &commands.Context{},
			cmd:    &fakeCmd{validateErr: errValidateFailed},
			checks: []func() error{passing}, wantErr: errValidateFailed.Error(), wantCalls: []string{"Validate"},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.cmd, tt.ctx, tt.checks...)

			assert.EqualError(t, err, tt.wantErr)
			assert.Equal(t, tt.wantCalls, tt.cmd.calls)
		})
	}
}
