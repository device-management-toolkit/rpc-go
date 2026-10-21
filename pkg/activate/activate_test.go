/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	internalact "github.com/device-management-toolkit/rpc-go/v2/internal/commands/activate"
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
)

const (
	authEndpoint    = "https://console.example.com/api/v1/authorize"
	devicesEndpoint = "https://console.example.com/api/v1/devices"
	profileURL      = "https://console.example.com/api/v1/admin/profiles/export/acm"
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
// really activate this device, so requireReachedAMT skips it.
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
// running call, which would activate this device.
func requireReachedAMT(t *testing.T, call func() error) {
	t.Helper()

	if amtReachable {
		t.Skip("skipped: this process is elevated and AMT is reachable over HECI, so the call would activate this device")
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

// missingExecutable is an rpc path that does not exist, so no test can run a real binary.
func missingExecutable(t *testing.T) string {
	t.Helper()

	return filepath.Join(t.TempDir(), "rpc")
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
		{"validation failed", errInvalidMode, false},
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
	executable := missingExecutable(t)

	tests := []struct {
		name string
		call func() error
	}{
		{"Local CCM", func() error { return Local(LocalOptions{Mode: ModeCCM}) }},
		{"Local CCM with password", func() error {
			return Local(LocalOptions{Mode: ModeCCM, AMTPassword: "P@ssw0rd"})
		}},
		{"Local ACM", func() error {
			return Local(LocalOptions{
				Mode: ModeACM, AMTPassword: "P@ssw0rd", MEBxPassword: "P@ssw0rd",
				ProvisioningCert: "cert", ProvisioningCertPassword: "certpass",
			})
		}},
		{"Local with Console token", func() error {
			return Local(LocalOptions{Mode: ModeCCM, AuthEndpoint: authEndpoint, AuthToken: "token"})
		}},
		{"Local with Console credentials", func() error {
			return Local(LocalOptions{
				Mode: ModeCCM, AuthEndpoint: authEndpoint, AuthUsername: "user", AuthPassword: "pass",
				DevicesEndpoint: devicesEndpoint,
			})
		}},
		{"StopConfiguration", func() error { return StopConfiguration(StopConfigurationOptions{}) }},
		{"Remote", func() error { return Remote(RemoteOptions{URL: rpsURL, Profile: "acm"}) }},
		{"Remote with upper-case ws scheme and proxy", func() error {
			return Remote(RemoteOptions{URL: "WS://rps.example.com/activate", Profile: "ccm", Proxy: "http://proxy.example.com:8080"})
		}},
		{"Profile file", func() error {
			return Profile(ProfileOptions{File: "profiles/acm.yaml", Executable: executable})
		}},
		{"Profile bare file name", func() error {
			// The command would take a bare name as an RPS profile name and reject it without a ws(s) URL.
			return Profile(ProfileOptions{File: "acm", Executable: executable})
		}},
		{"Profile file with Console", func() error {
			return Profile(ProfileOptions{
				File: "profiles/acm.yaml", Key: "key", Executable: executable,
				AuthEndpoint: authEndpoint, AuthToken: "token",
			})
		}},
		{"Profile URL", func() error {
			return Profile(ProfileOptions{URL: profileURL, AuthToken: "token", Executable: executable})
		}},
		{"Profile URL with an auth endpoint relative to the URL", func() error {
			return Profile(ProfileOptions{
				URL: profileURL, Executable: executable,
				AuthEndpoint: "/api/v1/authorize", AuthUsername: "user", AuthPassword: "pass",
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
	executable := missingExecutable(t)

	tests := []struct {
		name    string
		call    func() error
		wantErr string
	}{
		{
			name:    "Local without mode",
			call:    func() error { return Local(LocalOptions{AMTPassword: "P@ssw0rd"}) },
			wantErr: "must specify either ModeCCM or ModeACM",
		},
		{
			name:    "Local with unknown mode",
			call:    func() error { return Local(LocalOptions{Mode: ModeACM + 1}) },
			wantErr: "must specify either ModeCCM or ModeACM",
		},
		{
			name:    "Local ACM without provisioning certificate",
			call:    func() error { return Local(LocalOptions{Mode: ModeACM, ProvisioningCertPassword: "certpass"}) },
			wantErr: "provisioning certificate is required for ACM activation",
		},
		{
			name:    "Local ACM without provisioning certificate password",
			call:    func() error { return Local(LocalOptions{Mode: ModeACM, ProvisioningCert: "cert"}) },
			wantErr: "provisioning certificate password is required for ACM activation",
		},
		{
			name: "Local with relative auth endpoint",
			call: func() error {
				return Local(LocalOptions{Mode: ModeCCM, AuthEndpoint: "/api/v1/authorize", AuthToken: "token"})
			},
			wantErr: "AuthEndpoint must be an absolute HTTP(S) URL",
		},
		{
			name:    "Local with auth endpoint but no credentials",
			call:    func() error { return Local(LocalOptions{Mode: ModeCCM, AuthEndpoint: authEndpoint}) },
			wantErr: "--auth-endpoint requires --auth-token or both --auth-username and --auth-password",
		},
		{
			name:    "Local with username but no password",
			call:    func() error { return Local(LocalOptions{Mode: ModeCCM, AuthUsername: "user"}) },
			wantErr: "--auth-username requires --auth-password",
		},
		{
			name:    "Local with relative devices endpoint",
			call:    func() error { return Local(LocalOptions{Mode: ModeCCM, DevicesEndpoint: "/api/v1/devices"}) },
			wantErr: "--devices-endpoint must be an absolute HTTP(S) URL",
		},
		{
			name:    "Remote without URL",
			call:    func() error { return Remote(RemoteOptions{Profile: "acm"}) },
			wantErr: "RPS server URL is required",
		},
		{
			name:    "Remote without profile",
			call:    func() error { return Remote(RemoteOptions{URL: rpsURL}) },
			wantErr: "--profile is required for remote activation with ws/wss URLs",
		},
		{
			name:    "Remote with HTTPS URL",
			call:    func() error { return Remote(RemoteOptions{URL: "https://rps.example.com", Profile: "acm"}) },
			wantErr: "unsupported url scheme: https://rps.example.com",
		},
		{
			name:    "Remote with unparsable proxy",
			call:    func() error { return Remote(RemoteOptions{URL: rpsURL, Profile: "acm", Proxy: "://proxy"}) },
			wantErr: "invalid Proxy",
		},
		{
			name:    "Profile without file or URL",
			call:    func() error { return Profile(ProfileOptions{Executable: executable}) },
			wantErr: "exactly one of File and URL must be set",
		},
		{
			name: "Profile with file and URL",
			call: func() error {
				return Profile(ProfileOptions{File: "acm.yaml", URL: profileURL, Executable: executable})
			},
			wantErr: "exactly one of File and URL must be set",
		},
		{
			name:    "Profile with WebSocket URL",
			call:    func() error { return Profile(ProfileOptions{URL: rpsURL, Executable: executable}) },
			wantErr: "unsupported url scheme: " + rpsURL,
		},
		{
			name:    "Profile without executable",
			call:    func() error { return Profile(ProfileOptions{File: "acm.yaml"}) },
			wantErr: "missing Executable",
		},
		{
			name: "Profile file with relative auth endpoint",
			call: func() error {
				return Profile(ProfileOptions{
					File: "acm.yaml", Executable: executable, AuthEndpoint: "/api/v1/authorize", AuthToken: "token",
				})
			},
			wantErr: "AuthEndpoint must be an absolute HTTP(S) URL",
		},
		{
			name: "Profile with username but no password",
			call: func() error {
				return Profile(ProfileOptions{URL: profileURL, Executable: executable, AuthUsername: "user"})
			},
			wantErr: "--auth-username requires --auth-password",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorContains(t, tt.call(), tt.wantErr)
		})
	}
}

func TestNewLocalCommand_MapsOptions(t *testing.T) {
	cmd, ctx := newLocalCommand(LocalOptions{
		Mode:                     ModeACM,
		AMTPassword:              "amt-pass",
		ProvisioningCert:         "cert",
		ProvisioningCertPassword: "cert-pass",
		MEBxPassword:             "mebx-pass",
		SkipAMTCertCheck:         true,
		UUID:                     deviceUUID,
		Hostname:                 "10.0.0.5",
		FriendlyName:             "lab-01",
		SkipCertCheck:            true,
		TenantID:                 "tenant-1",
		AuthToken:                "token",
		AuthUsername:             "user",
		AuthPassword:             "pass",
		AuthEndpoint:             authEndpoint,
		DevicesEndpoint:          devicesEndpoint,
	})

	assert.Equal(t, &internalact.ActivateCmd{
		Local:               true,
		ACM:                 true,
		ProvisioningCert:    "cert",
		ProvisioningCertPwd: "cert-pass",
		MEBxPassword:        "mebx-pass",
		UUID:                deviceUUID,
		Hostname:            "10.0.0.5",
		FriendlyName:        "lab-01",
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

func TestNewLocalCommand_CCMSelectsCCMOnly(t *testing.T) {
	cmd, _ := newLocalCommand(LocalOptions{Mode: ModeCCM})

	assert.Equal(t, &internalact.ActivateCmd{Local: true, CCM: true}, cmd)
}

func TestNewStopConfigurationCommand(t *testing.T) {
	cmd, ctx := newStopConfigurationCommand(StopConfigurationOptions{})

	assert.Equal(t, &internalact.ActivateCmd{Local: true, StopConfig: true}, cmd)
	assert.Equal(t, &commands.Context{}, ctx)
}

func TestNewRemoteCommand_MapsOptions(t *testing.T) {
	cmd, ctx := newRemoteCommand(RemoteOptions{
		URL:              rpsURL,
		Profile:          "acm",
		AMTPassword:      "amt-pass",
		DNSSuffix:        "corp.example.com",
		Hostname:         "lab-01.corp.example.com",
		UUID:             deviceUUID,
		FriendlyName:     "lab-01",
		Proxy:            "http://proxy.example.com:8080",
		TLSTunnel:        true,
		TenantID:         "tenant-1",
		SkipCertCheck:    true,
		SkipAMTCertCheck: true,
	})

	assert.Equal(t, &internalact.ActivateCmd{
		URL:          rpsURL,
		Profile:      "acm",
		DNS:          "corp.example.com",
		Hostname:     "lab-01.corp.example.com",
		UUID:         deviceUUID,
		FriendlyName: "lab-01",
		Proxy:        "http://proxy.example.com:8080",
		TLSTunnel:    true,
	}, cmd)
	assert.Equal(t, &commands.Context{
		AMTPassword:      "amt-pass",
		SkipAMTCertCheck: true,
		SkipCertCheck:    true,
		TenantID:         "tenant-1",
	}, ctx)
}

func TestNewProfileCommand_MapsOptions(t *testing.T) {
	cmd, ctx := newProfileCommand(ProfileOptions{
		URL:              profileURL,
		Key:              "key",
		Executable:       "/opt/rpc/rpc",
		AMTPassword:      "amt-pass",
		MEBxPassword:     "mebx-pass",
		SkipAMTCertCheck: true,
		UUID:             deviceUUID,
		Hostname:         "10.0.0.5",
		FriendlyName:     "lab-01",
		SkipCertCheck:    true,
		TenantID:         "tenant-1",
		AuthToken:        "token",
		AuthUsername:     "user",
		AuthPassword:     "pass",
		AuthEndpoint:     "/api/v1/authorize",
		DevicesEndpoint:  devicesEndpoint,
	})

	assert.Equal(t, &internalact.ActivateCmd{
		URL:          profileURL,
		Key:          "key",
		Executable:   "/opt/rpc/rpc",
		MEBxPassword: "mebx-pass",
		UUID:         deviceUUID,
		Hostname:     "10.0.0.5",
		FriendlyName: "lab-01",
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

func TestNewProfileCommand_FileIsAlwaysAPath(t *testing.T) {
	// The activate command treats a bare name as an RPS profile name, so a file
	// in the working directory gets an explicit directory.
	tests := []struct {
		name        string
		file        string
		wantProfile string
	}{
		{"path with a directory", "profiles/acm.yaml", "profiles/acm.yaml"},
		{"bare file name", "acm", "." + string(filepath.Separator) + "acm"},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			cmd, _ := newProfileCommand(ProfileOptions{File: tt.file, Executable: "/opt/rpc/rpc"})

			assert.Equal(t, &internalact.ActivateCmd{Profile: tt.wantProfile, Executable: "/opt/rpc/rpc"}, cmd)
		})
	}
}

// fakeCmd stands in for the activate command. Run opens the client, as EnsureWSMAN does.
type fakeCmd struct {
	client interfaces.WSMANer
	runErr error
	wsman  interfaces.WSMANer
}

func (f *fakeCmd) Validate() error                    { return nil }
func (f *fakeCmd) AfterApply(amt.Interface) error     { return nil }
func (f *fakeCmd) GetWSManClient() interfaces.WSMANer { return f.wsman }

func (f *fakeCmd) Run(*commands.Context) error {
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

			err := run(&fakeCmd{client: client, runErr: tt.runErr}, &commands.Context{})

			assert.Equal(t, tt.runErr, err)
		})
	}
}

func TestRunWithoutWSMANClient(t *testing.T) {
	assert.NoError(t, run(&fakeCmd{}, &commands.Context{}))
}
