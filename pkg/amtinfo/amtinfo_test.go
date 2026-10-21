/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amtinfo

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const devicesURL = "https://console.example.com/api/v1/devices"

var errUnexpectedPrompt = errors.New("unexpected password prompt")

// noPrompt fails every password prompt so a test can never block on stdin.
type noPrompt struct{}

func (noPrompt) ReadPassword() (string, error) { return "", errUnexpectedPrompt }

func (noPrompt) ReadPasswordWithConfirmation(_, _ string) (string, error) {
	return "", errUnexpectedPrompt
}

func TestMain(m *testing.M) {
	utils.PR = noPrompt{}

	os.Exit(m.Run())
}

// requireRead asserts validation passed and the read returned a result. Test
// machines have no HECI, so the result says so, and the error is
// IncorrectPermissions unless the process is elevated: windows runners run as
// Administrator without a HECI driver.
func requireRead(t *testing.T, result *Result, err error) {
	t.Helper()

	require.NotNil(t, result, "expected a result, got error: %v", err)
	require.NotNil(t, result.HECIAvailable)

	if !*result.HECIAvailable && !utils.IsElevated() {
		require.ErrorIs(t, err, utils.IncorrectPermissions)

		return
	}

	require.NoError(t, err)
}

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

func TestGet_ReadsSelectedInformation(t *testing.T) {
	tests := []struct {
		name         string
		opts         Options
		wantHostname bool
	}{
		{"defaults", Options{}, true},
		{"all", Options{All: true}, true},
		{"hostname only", Options{Hostname: true}, true},
		{"selection without hostname", Options{Version: true, ControlMode: true}, false},
		{"password with a WSMAN-only selection is accepted", Options{
			UserCertificates: true, Proxy: true, AMTPassword: "P@ssw0rd", SkipAMTCertCheck: true,
		}, false},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			result, err := Get(tt.opts)

			requireRead(t, result, err)
			assert.Equal(t, tt.wantHostname, result.HostnameOS != "")
		})
	}
}

func TestGet_DoesNotWriteToStdout(t *testing.T) {
	var (
		result *Result
		err    error
	)

	out := captureStdout(t, func() { result, err = Get(Options{}) })

	requireRead(t, result, err)
	assert.Empty(t, out)
}

func TestSync_InvalidOptionsRejectedBeforeAMTAccess(t *testing.T) {
	tests := []struct {
		name    string
		opts    SyncOptions
		wantErr string
	}{
		{"missing URL", SyncOptions{}, "--url is required when --sync (aliases --discover or --register) is specified"},
		{"blank URL", SyncOptions{URL: " "}, "--url is required when --sync (aliases --discover or --register) is specified"},
		{"unparsable URL", SyncOptions{URL: "not a url"}, `invalid --url: parse "not a url": invalid URI for request`},
		{"username without password", SyncOptions{URL: devicesURL, AuthUsername: "user"}, "--auth-username requires --auth-password"},
		{"password without username", SyncOptions{URL: devicesURL, AuthPassword: "pass"}, "--auth-password requires --auth-username"},
		{
			"auth endpoint without credentials",
			SyncOptions{URL: devicesURL, AuthEndpoint: "/api/v1/authorize"},
			"--auth-endpoint requires --auth-token or both --auth-username and --auth-password",
		},
		{"auth checked before URL, as on the CLI", SyncOptions{AuthUsername: "user"}, "--auth-username requires --auth-password"},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			result, err := Sync(tt.opts)

			assert.Nil(t, result)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSync_ValidOptionsReadAndSync(t *testing.T) {
	var patches int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)

		if r.Method == http.MethodPatch {
			patches++
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := Sync(SyncOptions{URL: server.URL + "/api/v1/devices", AuthToken: "token", TenantID: "tenant-1"})

	// Without HECI the UUID comes from SMBIOS, which Linux exposes only to root:
	// the sync then fails before it sends anything. Where SMBIOS is readable,
	// as on windows runners, the device syncs to the local server.
	if err != nil && !errors.Is(err, utils.IncorrectPermissions) {
		require.ErrorContains(t, err, "device sync failed: cannot sync:")
		assert.Nil(t, result)
		assert.Zero(t, patches)

		return
	}

	requireRead(t, result, err)
	assert.Equal(t, 1, patches)
}

func TestNewCommand_MapsOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantCmd commands.AmtInfoCmd
		wantCtx commands.Context
	}{
		{name: "zero value"},
		{name: "Version", opts: Options{Version: true}, wantCmd: commands.AmtInfoCmd{Ver: true}},
		{name: "BuildNumber", opts: Options{BuildNumber: true}, wantCmd: commands.AmtInfoCmd{Bld: true}},
		{name: "SKU", opts: Options{SKU: true}, wantCmd: commands.AmtInfoCmd{Sku: true}},
		{name: "UUID", opts: Options{UUID: true}, wantCmd: commands.AmtInfoCmd{UUID: true}},
		{name: "UPID", opts: Options{UPID: true}, wantCmd: commands.AmtInfoCmd{UPID: true}},
		{name: "ControlMode", opts: Options{ControlMode: true}, wantCmd: commands.AmtInfoCmd{Mode: true}},
		{name: "ProvisioningState", opts: Options{ProvisioningState: true}, wantCmd: commands.AmtInfoCmd{ProvState: true}},
		{name: "DNSSuffix", opts: Options{DNSSuffix: true}, wantCmd: commands.AmtInfoCmd{DNS: true}},
		{name: "Hostname", opts: Options{Hostname: true}, wantCmd: commands.AmtInfoCmd{Hostname: true}},
		{name: "LAN", opts: Options{LAN: true}, wantCmd: commands.AmtInfoCmd{Lan: true}},
		{name: "RemoteAccess", opts: Options{RemoteAccess: true}, wantCmd: commands.AmtInfoCmd{Ras: true}},
		{name: "OperationalState", opts: Options{OperationalState: true}, wantCmd: commands.AmtInfoCmd{OpState: true}},
		{name: "CertificateHashes", opts: Options{CertificateHashes: true}, wantCmd: commands.AmtInfoCmd{Cert: true}},
		{name: "UserCertificates", opts: Options{UserCertificates: true}, wantCmd: commands.AmtInfoCmd{UserCert: true}},
		{name: "Proxy", opts: Options{Proxy: true}, wantCmd: commands.AmtInfoCmd{Proxy: true}},
		{name: "All", opts: Options{All: true}, wantCmd: commands.AmtInfoCmd{All: true}},
		{name: "AMTPassword", opts: Options{AMTPassword: "amt-pass"}, wantCtx: commands.Context{AMTPassword: "amt-pass"}},
		{name: "SkipAMTCertCheck", opts: Options{SkipAMTCertCheck: true}, wantCtx: commands.Context{SkipAMTCertCheck: true}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			cmd, ctx := newCommand(tt.opts)

			assert.Equal(t, &tt.wantCmd, cmd)
			assert.Equal(t, &tt.wantCtx, ctx)
		})
	}
}

func TestNewSyncCommand_MapsOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    SyncOptions
		wantCtx commands.Context
	}{
		{
			name: "credentials and tenant",
			opts: SyncOptions{
				URL:          devicesURL,
				AMTPassword:  "amt-pass",
				TenantID:     "tenant-1",
				AuthToken:    "token",
				AuthUsername: "user",
				AuthPassword: "pass",
				AuthEndpoint: "https://console.example.com/api/v1/authorize",
			},
			wantCtx: commands.Context{
				AMTPassword: "amt-pass",
				TenantID:    "tenant-1",
				ServerAuthFlags: commands.ServerAuthFlags{
					AuthToken:    "token",
					AuthUsername: "user",
					AuthPassword: "pass",
					AuthEndpoint: "https://console.example.com/api/v1/authorize",
				},
			},
		},
		{
			name:    "SkipAMTCertCheck",
			opts:    SyncOptions{URL: devicesURL, SkipAMTCertCheck: true},
			wantCtx: commands.Context{SkipAMTCertCheck: true},
		},
		{
			name:    "SkipCertCheck",
			opts:    SyncOptions{URL: devicesURL, SkipCertCheck: true},
			wantCtx: commands.Context{SkipCertCheck: true},
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			cmd, ctx := newSyncCommand(tt.opts)

			assert.Equal(t, &commands.AmtInfoCmd{Sync: true, URL: devicesURL}, cmd)
			assert.Equal(t, &tt.wantCtx, ctx)
		})
	}
}
