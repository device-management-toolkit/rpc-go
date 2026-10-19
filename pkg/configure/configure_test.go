/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"os"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var (
	errUnexpectedPrompt = errors.New("unexpected password prompt")
	errRunFailed        = errors.New("run failed")
	errCloseFailed      = errors.New("close failed")
)

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

// requireReachedAMT asserts validation passed and the call failed only on AMT access.
func requireReachedAMT(t *testing.T, err error) {
	t.Helper()

	if !errors.Is(err, utils.IncorrectPermissions) && !errors.Is(err, utils.HECIDriverNotDetected) {
		t.Fatalf("expected validation to pass and AMT access to fail, got: %v", err)
	}
}

func TestValidOptionsReachAMTWithoutPrompting(t *testing.T) {
	dhcp := true

	tests := []struct {
		name string
		call func() error
	}{
		{"SyncClock", func() error { return SyncClock(BaseOptions{}) }},
		{"SyncHostname", func() error { return SyncHostname(BaseOptions{}) }},
		{"EnableAMT", func() error { return EnableAMT(BaseOptions{}) }},
		{"DisableAMT", func() error { return DisableAMT(BaseOptions{}) }},
		{"ChangeAMTPassword", func() error {
			return ChangeAMTPassword(AMTPasswordOptions{NewPassword: "NewP@ssw0rd"})
		}},
		{"SetMEBx", func() error { return SetMEBx(MEBxOptions{MEBxPassword: "P@ssw0rd"}) }},
		{"SetAMTFeatures", func() error { return SetAMTFeatures(AMTFeaturesOptions{KVM: true}) }},
		{"ConfigureWiFiSync", func() error { return ConfigureWiFiSync(WiFiSyncOptions{OSWiFiSync: true}) }},
		{"ConfigureWireless", func() error {
			return ConfigureWireless(WirelessOptions{
				ProfileName: "wifi1", SSID: "ssid", Priority: 1,
				AuthenticationMethod: 6, EncryptionMethod: 4, PSKPassphrase: "passphrase",
			})
		}},
		{"ConfigureWireless purge", func() error { return ConfigureWireless(WirelessOptions{Purge: true}) }},
		{"ConfigureWireless purge ignores 802.1x protocol", func() error {
			return ConfigureWireless(WirelessOptions{Purge: true, IEEE8021xAuthenticationProtocol: 1})
		}},
		{"ConfigureWired", func() error { return ConfigureWired(WiredOptions{DHCPEnabled: &dhcp}) }},
		{"ConfigureTLS", func() error { return ConfigureTLS(TLSOptions{}) }},
		{"ConfigureTLS with EA", func() error {
			return ConfigureTLS(TLSOptions{EAAddress: "https://ea.example.com", EAUsername: "user", EAPassword: "pass"})
		}},
		{"ConfigureCIRA", func() error {
			return ConfigureCIRA(CIRAOptions{MPSAddress: "mps.example.com", MPSCert: "cert", MPSPassword: "P@ssw0rd"})
		}},
		{"ConfigureCIRA random password", func() error {
			return ConfigureCIRA(CIRAOptions{MPSAddress: "mps.example.com", MPSCert: "cert", GenerateRandomPassword: true})
		}},
		{"ConfigureProxy list", func() error { return ConfigureProxy(ProxyOptions{List: true}) }},
		{"ConfigureProxy add", func() error {
			return ConfigureProxy(ProxyOptions{Address: "proxy.example.com", NetworkDnsSuffix: "example.com"})
		}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			requireReachedAMT(t, tt.call())
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
			name: "CIRA address with scheme",
			call: func() error {
				return ConfigureCIRA(CIRAOptions{MPSAddress: "https://mps.example.com", MPSPassword: "P@ssw0rd"})
			},
			wantErr: "invalid MPS address format",
		},
		{
			name: "wireless PEAP-MSCHAPv2 without password",
			call: func() error {
				return ConfigureWireless(WirelessOptions{
					ProfileName: "wifi1", SSID: "ssid", Priority: 1,
					AuthenticationMethod: 7, EncryptionMethod: 4,
					IEEE8021xProfileName: "wifi1x", IEEE8021xAuthenticationProtocol: 2,
				})
			},
			wantErr: "IEEE 802.1x password is required for PEAP-MSCHAPv2",
		},
		{
			name: "wireless keeps an explicit authentication method",
			call: func() error {
				return ConfigureWireless(WirelessOptions{
					ProfileName: "wifi1", SSID: "ssid", AuthenticationMethod: 7, PSKPassphrase: "passphrase",
				})
			},
			wantErr: "PSK passphrase should not be specified for IEEE 802.1x",
		},
		{
			name: "CIRA without MPS cert",
			call: func() error {
				return ConfigureCIRA(CIRAOptions{MPSAddress: "mps.example.com", MPSPassword: "P@ssw0rd"})
			},
			wantErr: "MPS root certificate is required",
		},
		{
			name:    "AMT features with invalid user consent",
			call:    func() error { return SetAMTFeatures(AMTFeaturesOptions{KVM: true, UserConsent: "sometimes"}) },
			wantErr: "invalid user consent",
		},
		{
			name: "wired with unsupported 802.1x protocol",
			call: func() error {
				dhcp := true

				return ConfigureWired(WiredOptions{DHCPEnabled: &dhcp, IEEE8021xAuthenticationProtocol: 1})
			},
			wantErr: "invalid IEEE 802.1x authentication protocol",
		},
		{
			name: "wireless with unsupported 802.1x protocol",
			call: func() error {
				return ConfigureWireless(WirelessOptions{
					ProfileName: "wifi1", SSID: "ssid", AuthenticationMethod: 7,
					IEEE8021xProfileName: "wifi1x", IEEE8021xPassword: "secret", IEEE8021xAuthenticationProtocol: 1,
				})
			},
			wantErr: "invalid IEEE 802.1x authentication protocol",
		},
		{
			name:    "proxy list and delete together",
			call:    func() error { return ConfigureProxy(ProxyOptions{List: true, Delete: true}) },
			wantErr: "cannot use --list and --delete flags together",
		},
		{
			name:    "wired without DHCP or static settings",
			call:    func() error { return ConfigureWired(WiredOptions{}) },
			wantErr: "must specify -dhcp or static IP settings",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorContains(t, tt.call(), tt.wantErr)
		})
	}
}

// fakeCmd stands in for an internal command. Run opens the client, as EnsureWSMAN does.
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

			err := run(&fakeCmd{client: client, runErr: tt.runErr}, BaseOptions{})

			assert.Equal(t, tt.runErr, err)
		})
	}
}

func TestRunWithoutWSMANClient(t *testing.T) {
	assert.NoError(t, run(&fakeCmd{}, BaseOptions{}))
}

func TestConfigureWireless_AppliesCLIDefaults(t *testing.T) {
	// Priority, AuthenticationMethod and EncryptionMethod fall back to 1, WPA2-PSK and CCMP.
	err := ConfigureWireless(WirelessOptions{ProfileName: "wifi1", SSID: "ssid", PSKPassphrase: "passphrase"})

	requireReachedAMT(t, err)
}
