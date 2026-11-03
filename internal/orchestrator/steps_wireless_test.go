/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"errors"
	"fmt"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/configure"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/require"
)

// stubConfigureWireless replaces configureWireless for the test. The stub
// records the options of every call and returns errs in order, then nil.
func stubConfigureWireless(t *testing.T, errs ...error) *[]configure.WirelessOptions {
	t.Helper()

	var calls []configure.WirelessOptions

	orig := configureWireless
	configureWireless = func(opts configure.WirelessOptions) error {
		calls = append(calls, opts)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	t.Cleanup(func() { configureWireless = orig })

	return &calls
}

// wirelessPurgeOpts is the options struct of the purge call: Purge and the
// base options only.
func wirelessPurgeOpts(amtPassword string, skipAMTCertCheck bool) configure.WirelessOptions {
	return configure.WirelessOptions{
		BaseOptions: configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: skipAMTCertCheck},
		Purge:       true,
	}
}

// pskWirelessProfile is a WPA2-PSK/CCMP wireless profile.
func pskWirelessProfile() config.WirelessProfile {
	return config.WirelessProfile{
		ProfileName:          "home",
		SSID:                 "home-ssid",
		Password:             "psk-secret",
		AuthenticationMethod: "WPA2PSK",
		EncryptionMethod:     "CCMP",
		Priority:             2,
	}
}

// pskWirelessOpts is the options struct the step is expected to pass for
// pskWirelessProfile.
func pskWirelessOpts(amtPassword string, skipAMTCertCheck bool) configure.WirelessOptions {
	return configure.WirelessOptions{
		BaseOptions:          configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: skipAMTCertCheck},
		ProfileName:          "home",
		SSID:                 "home-ssid",
		Priority:             2,
		AuthenticationMethod: 6,
		EncryptionMethod:     4,
		PSKPassphrase:        "psk-secret",
	}
}

// wirelessProfileConfig is an activated-device profile with an AdminPassword
// and the given wireless profiles.
func wirelessProfileConfig(profiles ...config.WirelessProfile) config.Configuration {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pass"
	cfg.Configuration.Network.Wireless.Profiles = profiles

	return cfg
}

func TestExecuteWirelessConfigurations_MapsOptions(t *testing.T) {
	tests := []struct {
		name     string
		profiles []config.WirelessProfile
		want     func(amtPassword string, skip bool) []configure.WirelessOptions
	}{
		{
			name: "purge only",
			want: func(pw string, skip bool) []configure.WirelessOptions {
				return []configure.WirelessOptions{wirelessPurgeOpts(pw, skip)}
			},
		},
		{
			name:     "PSK",
			profiles: []config.WirelessProfile{pskWirelessProfile()},
			want: func(pw string, skip bool) []configure.WirelessOptions {
				return []configure.WirelessOptions{wirelessPurgeOpts(pw, skip), pskWirelessOpts(pw, skip)}
			},
		},
		{
			name: "WPA-PSK with TKIP",
			profiles: []config.WirelessProfile{{
				ProfileName: "legacy", SSID: "legacy-ssid", Password: "legacy-psk",
				AuthenticationMethod: "wpapsk", EncryptionMethod: "tkip", Priority: 7,
			}},
			want: func(pw string, skip bool) []configure.WirelessOptions {
				return []configure.WirelessOptions{wirelessPurgeOpts(pw, skip), {
					BaseOptions: configure.BaseOptions{AMTPassword: pw, SkipAMTCertCheck: skip},
					ProfileName: "legacy", SSID: "legacy-ssid", Priority: 7,
					AuthenticationMethod: 4, EncryptionMethod: 3, PSKPassphrase: "legacy-psk",
				}}
			},
		},
		{
			name: "802.1x PEAP with certificates",
			profiles: []config.WirelessProfile{{
				ProfileName: "corp", SSID: "corp-ssid",
				AuthenticationMethod: "WPA2IEEE8021X", EncryptionMethod: "CCMP", Priority: 1,
				IEEE8021x: &config.IEEE8021x{
					Username: "user", Password: "eap-secret", AuthenticationProtocol: 2,
					PrivateKey: "key-data", ClientCert: "client-cert-data", CACert: "ca-cert-data",
				},
			}},
			want: func(pw string, skip bool) []configure.WirelessOptions {
				return []configure.WirelessOptions{wirelessPurgeOpts(pw, skip), {
					BaseOptions: configure.BaseOptions{AMTPassword: pw, SkipAMTCertCheck: skip},
					ProfileName: "corp", SSID: "corp-ssid", Priority: 1,
					AuthenticationMethod: 7, EncryptionMethod: 4,
					IEEE8021xProfileName:            "corp_8021x",
					IEEE8021xUsername:               "user",
					IEEE8021xPassword:               "eap-secret",
					IEEE8021xAuthenticationProtocol: 2,
					IEEE8021xPrivateKey:             "key-data",
					IEEE8021xClientCert:             "client-cert-data",
					IEEE8021xCACert:                 "ca-cert-data",
				}}
			},
		},
		{
			// The old step left out --ieee8021xAuthenticationProtocol for 0,
			// which gave Kong's default 0, so passing 0 is the same value.
			name: "802.1x EAP-TLS with certificates only",
			profiles: []config.WirelessProfile{{
				ProfileName: "tls", SSID: "tls-ssid",
				AuthenticationMethod: "WPA2IEEE8021X", EncryptionMethod: "CCMP", Priority: 3,
				IEEE8021x: &config.IEEE8021x{ClientCert: "client-cert-data", CACert: "ca-cert-data"},
			}},
			want: func(pw string, skip bool) []configure.WirelessOptions {
				return []configure.WirelessOptions{wirelessPurgeOpts(pw, skip), {
					BaseOptions: configure.BaseOptions{AMTPassword: pw, SkipAMTCertCheck: skip},
					ProfileName: "tls", SSID: "tls-ssid", Priority: 3,
					AuthenticationMethod: 7, EncryptionMethod: 4,
					IEEE8021xProfileName: "tls_8021x",
					IEEE8021xClientCert:  "client-cert-data",
					IEEE8021xCACert:      "ca-cert-data",
				}}
			},
		},
		{
			name:     "two profiles in order",
			profiles: []config.WirelessProfile{pskWirelessProfile(), {ProfileName: "guest", SSID: "guest-ssid", Password: "guest-psk", AuthenticationMethod: "WPA2PSK", EncryptionMethod: "CCMP", Priority: 9}},
			want: func(pw string, skip bool) []configure.WirelessOptions {
				return []configure.WirelessOptions{wirelessPurgeOpts(pw, skip), pskWirelessOpts(pw, skip), {
					BaseOptions: configure.BaseOptions{AMTPassword: pw, SkipAMTCertCheck: skip},
					ProfileName: "guest", SSID: "guest-ssid", Priority: 9,
					AuthenticationMethod: 6, EncryptionMethod: 4, PSKPassphrase: "guest-psk",
				}}
			},
		},
	}

	for _, tt := range tests {
		for _, skip := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/skipAMTCertCheck=%t", tt.name, skip), func(t *testing.T) {
				calls := stubConfigureWireless(t)

				po := NewProfileOrchestrator(wirelessProfileConfig(tt.profiles...), "", "", skip)
				po.currentControlMode = 2
				po.globalPassword = "current-pass"

				require.NoError(t, po.executeWirelessConfigurations())

				require.Equal(t, tt.want("current-pass", skip), *calls)
			})
		}
	}
}

func TestExecuteWirelessConfigurations_Logs(t *testing.T) {
	t.Run("purge only", func(t *testing.T) {
		hook := captureLogs(t)
		stubConfigureWireless(t)

		po := NewProfileOrchestrator(config.Configuration{}, "", "", false)

		require.NoError(t, po.executeWirelessConfigurations())

		require.True(t, loggedMessage(hook, "Purging existing AMT wireless profiles before applying new configuration"))
		require.True(t, loggedMessage(hook, "No wireless profiles specified in profile; nothing more to apply after purge"))
	})

	t.Run("one profile", func(t *testing.T) {
		hook := captureLogs(t)
		stubConfigureWireless(t)

		po := NewProfileOrchestrator(wirelessProfileConfig(pskWirelessProfile()), "", "", false)

		require.NoError(t, po.executeWirelessConfigurations())

		require.True(t, loggedMessage(hook, "Purging existing AMT wireless profiles before applying new configuration"))
		require.True(t, loggedMessage(hook, "Executing wireless profile configuration 1/1: home"))
		require.False(t, loggedMessage(hook, "No wireless profiles specified in profile; nothing more to apply after purge"))
	})
}

func TestExecuteWirelessConfigurations_PurgeFailureStops(t *testing.T) {
	calls := stubConfigureWireless(t, errors.New("purge broke"))

	po := NewProfileOrchestrator(wirelessProfileConfig(pskWirelessProfile()), "", "", false)

	err := po.executeWirelessConfigurations()
	require.EqualError(t, err, "wireless purge failed: purge broke")

	require.Equal(t, []configure.WirelessOptions{wirelessPurgeOpts("admin-pass", false)}, *calls)
}

func TestExecuteWirelessConfigurations_RejectsBeforeCall(t *testing.T) {
	// Each case fails before its pkg call: only the purge reaches the stub.
	tests := []struct {
		name    string
		profile func(*config.WirelessProfile)
		wantErr string
	}{
		{
			name:    "unparsable authentication method",
			profile: func(p *config.WirelessProfile) { p.AuthenticationMethod = "bogus" },
			wantErr: "invalid authentication method: bogus",
		},
		{
			name:    "unparsable encryption method",
			profile: func(p *config.WirelessProfile) { p.EncryptionMethod = "bogus" },
			wantErr: "invalid encryption method: bogus",
		},
		{
			name:    "zero priority",
			profile: func(p *config.WirelessProfile) { p.Priority = 0 },
			wantErr: "priority must be greater than 0",
		},
		{
			name:    "negative priority",
			profile: func(p *config.WirelessProfile) { p.Priority = -1 },
			wantErr: "priority must be greater than 0",
		},
		{
			name:    "authentication method outside the CLI enum",
			profile: func(p *config.WirelessProfile) { p.AuthenticationMethod = "WPAIEEE8021X" },
			wantErr: `authenticationMethod must be one of "4","6","7" but got "5"`,
		},
		{
			name:    "encryption method outside the CLI enum",
			profile: func(p *config.WirelessProfile) { p.EncryptionMethod = "WEP" },
			wantErr: `encryptionMethod must be one of "3","4" but got "2"`,
		},
		{
			name: "802.1x authentication protocol outside the CLI enum",
			profile: func(p *config.WirelessProfile) {
				p.AuthenticationMethod = "WPA2IEEE8021X"
				p.Password = ""
				p.IEEE8021x = &config.IEEE8021x{Username: "user", AuthenticationProtocol: 1}
			},
			wantErr: `ieee8021xAuthenticationProtocol must be one of "0","2" but got "1"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := stubConfigureWireless(t)

			profile := pskWirelessProfile()
			tt.profile(&profile)

			po := NewProfileOrchestrator(wirelessProfileConfig(profile), "", "", false)
			po.currentControlMode = 2
			po.globalPassword = "current-pass"

			err := po.executeWirelessConfigurations()
			require.EqualError(t, err, "failed to configure wireless profile home: "+tt.wantErr)

			require.Equal(t, []configure.WirelessOptions{wirelessPurgeOpts("current-pass", false)}, *calls,
				"the profile's pkg call must not run")
		})
	}
}

func TestExecuteWirelessConfigurations_AuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubConfigureWireless(t, nil, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(wirelessProfileConfig(pskWirelessProfile()), "old-pass", "", true)
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.executeWirelessConfigurations())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", true)}, *rotations)
	require.Equal(t, []configure.WirelessOptions{
		wirelessPurgeOpts("stale-pass", true),
		pskWirelessOpts("stale-pass", true),
		pskWirelessOpts("admin-pass", true),
	}, *calls)
	require.Equal(t, "admin-pass", po.globalPassword)
}

func TestExecuteWirelessConfigurations_PurgeAuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubConfigureWireless(t, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(wirelessProfileConfig(pskWirelessProfile()), "old-pass", "", false)
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.executeWirelessConfigurations())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", false)}, *rotations)
	require.Equal(t, []configure.WirelessOptions{
		wirelessPurgeOpts("stale-pass", false),
		wirelessPurgeOpts("admin-pass", false),
		pskWirelessOpts("admin-pass", false),
	}, *calls)
}

func TestExecuteWirelessConfigurations_SettleRetry(t *testing.T) {
	t.Run("retries a plain error", func(t *testing.T) {
		calls := stubConfigureWireless(t, nil, errors.New("connection reset while AMT settles"))

		po := NewProfileOrchestrator(wirelessProfileConfig(pskWirelessProfile()), "", "", false)
		po.currentControlMode = 2
		po.globalPassword = "admin-pass"
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.executeWirelessConfigurations())

		require.Equal(t, []configure.WirelessOptions{
			wirelessPurgeOpts("admin-pass", false),
			pskWirelessOpts("admin-pass", false),
			pskWirelessOpts("admin-pass", false),
		}, *calls)
	})

	t.Run("stops on device not activated", func(t *testing.T) {
		calls := stubConfigureWireless(t, utils.DeviceNotActivated, utils.DeviceNotActivated)

		po := NewProfileOrchestrator(wirelessProfileConfig(pskWirelessProfile()), "", "", false)
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.ErrorIs(t, po.executeWirelessConfigurations(), utils.DeviceNotActivated)

		require.Len(t, *calls, 1)
	})
}
