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

// stubConfigureTLS replaces configureTLS for the test. The stub records the
// options of every call and returns errs in order, then nil.
func stubConfigureTLS(t *testing.T, errs ...error) *[]configure.TLSOptions {
	t.Helper()

	var calls []configure.TLSOptions

	orig := configureTLS
	configureTLS = func(opts configure.TLSOptions) error {
		calls = append(calls, opts)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	t.Cleanup(func() { configureTLS = orig })

	return &calls
}

// tlsProfile is an activated-device profile with an AdminPassword and
// server-only TLS enabled.
func tlsProfile() config.Configuration {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pass"
	cfg.Configuration.TLS.Enabled = true

	return cfg
}

// tlsOpts is the options struct the TLS step for tlsProfile is expected to
// pass to pkg/configure.
func tlsOpts(amtPassword string, skipAMTCertCheck bool) configure.TLSOptions {
	return configure.TLSOptions{
		BaseOptions: configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: skipAMTCertCheck},
		Mode:        "Server",
	}
}

func TestExecuteTLSConfiguration_MapsMode(t *testing.T) {
	// Delay stays 0: pkg/configure applies 3, the CLI default the old child
	// got because the step never passed --delay.
	tests := []struct {
		mutual, allowNonTLS bool
		mode                string
	}{
		{false, false, "Server"},
		{false, true, "ServerAndNonTLS"},
		{true, false, "Mutual"},
		{true, true, "MutualAndNonTLS"},
	}

	for _, tt := range tests {
		for _, skip := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/skipAMTCertCheck=%t", tt.mode, skip), func(t *testing.T) {
				calls := stubConfigureTLS(t)

				cfg := config.Configuration{}
				cfg.Configuration.TLS.Enabled = true
				cfg.Configuration.TLS.MutualAuthentication = tt.mutual
				cfg.Configuration.TLS.AllowNonTLS = tt.allowNonTLS

				po := NewProfileOrchestrator(cfg, "", "", skip)
				executor := newMockExecutor()
				po.executor = executor
				po.currentControlMode = 2
				po.globalPassword = "current-pass"

				require.NoError(t, po.executeTLSConfiguration())

				require.Equal(t, []configure.TLSOptions{{
					BaseOptions: configure.BaseOptions{AMTPassword: "current-pass", SkipAMTCertCheck: skip},
					Mode:        tt.mode,
				}}, *calls)
				require.Equal(t, 0, executor.callCount, "the TLS step must not run the CLI")
			})
		}
	}
}

func TestExecuteTLSConfiguration_MapsEnterpriseAssistant(t *testing.T) {
	// EA fields go out only when the signing authority is not SelfSigned and
	// an EA URL is set; username and password only when non-empty. The EA
	// password comes from the profile only, never from EA_PASSWORD.
	tests := []struct {
		name             string
		signingAuthority string
		url              string
		username         string
		password         string
		wantAddress      string
		wantUsername     string
		wantPassword     string
	}{
		{
			name:             "SelfSigned ignores a configured EA",
			signingAuthority: "SelfSigned",
			url:              "https://ea.example.com", username: "ea-user", password: "ea-pass",
		},
		{
			name:             "MicrosoftCA without an EA URL",
			signingAuthority: "MicrosoftCA",
			username:         "ea-user", password: "ea-pass",
		},
		{
			name:             "MicrosoftCA with only an EA URL",
			signingAuthority: "MicrosoftCA",
			url:              "https://ea.example.com",
			wantAddress:      "https://ea.example.com",
		},
		{
			name:             "MicrosoftCA with a full EA",
			signingAuthority: "MicrosoftCA",
			url:              "https://ea.example.com", username: "ea-user", password: "ea-pass",
			wantAddress: "https://ea.example.com", wantUsername: "ea-user", wantPassword: "ea-pass",
		},
		{
			name: "empty signing authority with a full EA",
			url:  "https://ea.example.com", username: "ea-user", password: "ea-pass",
			wantAddress: "https://ea.example.com", wantUsername: "ea-user", wantPassword: "ea-pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("EA_PASSWORD", "env-ea-pass")

			calls := stubConfigureTLS(t)

			cfg := config.Configuration{}
			cfg.Configuration.TLS.Enabled = true
			cfg.Configuration.TLS.SigningAuthority = tt.signingAuthority
			cfg.Configuration.EnterpriseAssistant.URL = tt.url
			cfg.Configuration.EnterpriseAssistant.Username = tt.username
			cfg.Configuration.EnterpriseAssistant.Password = tt.password

			po := NewProfileOrchestrator(cfg, "", "", false)
			executor := newMockExecutor()
			po.executor = executor
			po.currentControlMode = 2
			po.globalPassword = "current-pass"

			require.NoError(t, po.executeTLSConfiguration())

			require.Equal(t, []configure.TLSOptions{{
				BaseOptions: configure.BaseOptions{AMTPassword: "current-pass"},
				Mode:        "Server",
				EAAddress:   tt.wantAddress,
				EAUsername:  tt.wantUsername,
				EAPassword:  tt.wantPassword,
			}}, *calls)
			require.Equal(t, 0, executor.callCount, "the TLS step must not run the CLI")
		})
	}
}

func TestExecuteTLSConfiguration_SkipsWhenDisabled(t *testing.T) {
	hook := captureLogs(t)
	calls := stubConfigureTLS(t)

	cfg := tlsProfile()
	cfg.Configuration.TLS.Enabled = false

	po := NewProfileOrchestrator(cfg, "", "", false)
	executor := newMockExecutor()
	po.executor = executor

	require.NoError(t, po.executeTLSConfiguration())

	require.Empty(t, *calls)
	require.Equal(t, 0, executor.callCount)
	require.True(t, loggedMessage(hook, "TLS not enabled, skipping TLS configuration"))
}

func TestExecuteTLSConfiguration_AuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubConfigureTLS(t, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(tlsProfile(), "old-pass", "", true)
	executor := newMockExecutor()
	po.executor = executor
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.executeTLSConfiguration())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", true)}, *rotations)
	require.Equal(t, []configure.TLSOptions{
		tlsOpts("stale-pass", true),
		tlsOpts("admin-pass", true),
	}, *calls)
	require.Equal(t, "admin-pass", po.globalPassword)
	require.Equal(t, 0, executor.callCount, "rotation and retry must not run the CLI")
}

func TestExecuteTLSConfiguration_SettleRetry(t *testing.T) {
	t.Run("retries a plain error", func(t *testing.T) {
		calls := stubConfigureTLS(t, errors.New("connection reset while AMT settles"))

		po := NewProfileOrchestrator(tlsProfile(), "", "", false)
		executor := newMockExecutor()
		po.executor = executor
		po.currentControlMode = 2
		po.globalPassword = "admin-pass"
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.executeTLSConfiguration())

		require.Equal(t, []configure.TLSOptions{
			tlsOpts("admin-pass", false),
			tlsOpts("admin-pass", false),
		}, *calls)
		require.Equal(t, 0, executor.callCount, "the settle retry must not run the CLI")
	})

	t.Run("stops on device not activated", func(t *testing.T) {
		calls := stubConfigureTLS(t, utils.DeviceNotActivated, utils.DeviceNotActivated)

		po := NewProfileOrchestrator(tlsProfile(), "", "", false)
		executor := newMockExecutor()
		po.executor = executor
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.ErrorIs(t, po.executeTLSConfiguration(), utils.DeviceNotActivated)

		require.Len(t, *calls, 1)
		require.Equal(t, 0, executor.callCount, "the settle retry must not run the CLI")
	})
}
