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

// stubConfigureCIRA replaces configureCIRA for the test. The stub records the
// options of every call and returns errs in order, then nil.
func stubConfigureCIRA(t *testing.T, errs ...error) *[]configure.CIRAOptions {
	t.Helper()

	var calls []configure.CIRAOptions

	orig := configureCIRA
	configureCIRA = func(opts configure.CIRAOptions) error {
		calls = append(calls, opts)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	t.Cleanup(func() { configureCIRA = orig })

	return &calls
}

// ciraProfile is an activated-device profile with an AdminPassword and the
// minimal CIRA settings (MPS address and certificate).
func ciraProfile() config.Configuration {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pass"
	cfg.Configuration.AMTSpecific.CIRA.MPSAddress = "mps.example.com"
	cfg.Configuration.AMTSpecific.CIRA.MPSCert = "cert-pem-data"

	return cfg
}

// ciraOpts is the options struct the CIRA step for ciraProfile is expected to
// pass to pkg/configure.
func ciraOpts(amtPassword string, skipAMTCertCheck bool) configure.CIRAOptions {
	return configure.CIRAOptions{
		BaseOptions: configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: skipAMTCertCheck},
		MPSAddress:  "mps.example.com",
		MPSCert:     "cert-pem-data",
	}
}

func TestExecuteCIRAConfiguration_MapsOptions(t *testing.T) {
	// Every field comes from the profile only, never from MPS_PASSWORD,
	// GENERATE_RANDOM_PASSWORD or ENVIRONMENT_DETECTION; an empty environment
	// detection list stays nil. Environment detection splits as Kong's
	// SplitEscaped did for the old child's --envdetection flag.
	tests := []struct {
		name                   string
		mpsPassword            string
		generateRandomPassword bool
		envDetection           []string
		wantEnvDetection       []string
	}{
		{name: "address and cert only"},
		{name: "MPS password", mpsPassword: "mps-secret"},
		{name: "generate random password", generateRandomPassword: true},
		{
			name:             "empty environment detection list",
			envDetection:     []string{},
			wantEnvDetection: nil,
		},
		{
			name:             "two environment detection strings",
			envDetection:     []string{"corp.example.com", "vpn.example.com"},
			wantEnvDetection: []string{"corp.example.com", "vpn.example.com"},
		},
		{
			name:             "comma inside an environment detection string splits",
			envDetection:     []string{"corp.example.com,vpn.example.com"},
			wantEnvDetection: []string{"corp.example.com", "vpn.example.com"},
		},
		{
			name:             "only an empty environment detection string",
			envDetection:     []string{""},
			wantEnvDetection: nil,
		},
		{
			name:             "trailing empty environment detection string is dropped",
			envDetection:     []string{"x", ""},
			wantEnvDetection: []string{"x"},
		},
		{
			name:             "escaped comma inside an environment detection string stays literal",
			envDetection:     []string{"a\\,b"},
			wantEnvDetection: []string{"a,b"},
		},
		{
			name:                   "every field",
			mpsPassword:            "mps-secret",
			generateRandomPassword: true,
			envDetection:           []string{"corp.example.com"},
			wantEnvDetection:       []string{"corp.example.com"},
		},
	}

	for _, tt := range tests {
		for _, skip := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/skipAMTCertCheck=%t", tt.name, skip), func(t *testing.T) {
				t.Setenv("MPS_PASSWORD", "env-mps-pass")
				t.Setenv("ENVIRONMENT_DETECTION", "env.example.com")
				t.Setenv("GENERATE_RANDOM_PASSWORD", "true")

				calls := stubConfigureCIRA(t)

				cfg := ciraProfile()
				cfg.Configuration.AMTSpecific.CIRA.MPSPassword = tt.mpsPassword
				cfg.Configuration.AMTSpecific.CIRA.GenerateRandomPassword = tt.generateRandomPassword
				cfg.Configuration.AMTSpecific.CIRA.EnvironmentDetection = tt.envDetection

				po := NewProfileOrchestrator(cfg, "", "", skip)
				executor := newMockExecutor()
				po.executor = executor
				po.currentControlMode = 2
				po.globalPassword = "current-pass"

				require.NoError(t, po.executeCIRAConfiguration())

				want := ciraOpts("current-pass", skip)
				want.MPSPassword = tt.mpsPassword
				want.GenerateRandomPassword = tt.generateRandomPassword
				want.EnvironmentDetection = tt.wantEnvDetection

				require.Equal(t, []configure.CIRAOptions{want}, *calls)
				require.Equal(t, 0, executor.callCount, "the CIRA step must not run the CLI")
			})
		}
	}
}

func TestExecuteCIRAConfiguration_SkipsWhenNotConfigured(t *testing.T) {
	tests := []struct {
		name       string
		mpsAddress string
		mpsCert    string
	}{
		{name: "neither"},
		{name: "address only", mpsAddress: "mps.example.com"},
		{name: "cert only", mpsCert: "cert-pem-data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := captureLogs(t)
			calls := stubConfigureCIRA(t)

			cfg := ciraProfile()
			cfg.Configuration.AMTSpecific.CIRA.MPSAddress = tt.mpsAddress
			cfg.Configuration.AMTSpecific.CIRA.MPSCert = tt.mpsCert
			cfg.Configuration.AMTSpecific.CIRA.MPSPassword = "mps-secret"

			po := NewProfileOrchestrator(cfg, "pwd", "", false)
			executor := newMockExecutor()
			po.executor = executor

			require.NoError(t, po.executeCIRAConfiguration())

			require.Empty(t, *calls)
			require.Equal(t, 0, executor.callCount)
			require.True(t, loggedMessage(hook, "No CIRA configuration specified, skipping"))
		})
	}
}

func TestExecuteCIRAConfiguration_AuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubConfigureCIRA(t, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(ciraProfile(), "old-pass", "", true)
	executor := newMockExecutor()
	po.executor = executor
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.executeCIRAConfiguration())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", true)}, *rotations)
	require.Equal(t, []configure.CIRAOptions{
		ciraOpts("stale-pass", true),
		ciraOpts("admin-pass", true),
	}, *calls)
	require.Equal(t, "admin-pass", po.globalPassword)
	require.Equal(t, 0, executor.callCount, "rotation and retry must not run the CLI")
}

func TestExecuteCIRAConfiguration_SettleRetry(t *testing.T) {
	t.Run("retries a plain error", func(t *testing.T) {
		calls := stubConfigureCIRA(t, errors.New("connection reset while AMT settles"))

		po := NewProfileOrchestrator(ciraProfile(), "", "", false)
		executor := newMockExecutor()
		po.executor = executor
		po.currentControlMode = 2
		po.globalPassword = "admin-pass"
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.executeCIRAConfiguration())

		require.Equal(t, []configure.CIRAOptions{
			ciraOpts("admin-pass", false),
			ciraOpts("admin-pass", false),
		}, *calls)
		require.Equal(t, 0, executor.callCount, "the settle retry must not run the CLI")
	})

	t.Run("stops on device not activated", func(t *testing.T) {
		calls := stubConfigureCIRA(t, utils.DeviceNotActivated, utils.DeviceNotActivated)

		po := NewProfileOrchestrator(ciraProfile(), "", "", false)
		executor := newMockExecutor()
		po.executor = executor
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.ErrorIs(t, po.executeCIRAConfiguration(), utils.DeviceNotActivated)

		require.Len(t, *calls, 1)
		require.Equal(t, 0, executor.callCount, "the settle retry must not run the CLI")
	})
}
