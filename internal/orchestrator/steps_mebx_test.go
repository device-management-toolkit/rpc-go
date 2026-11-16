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

// stubSetMEBx replaces configureSetMEBx for the test. The stub records the
// options of every call and returns errs in order, then nil.
func stubSetMEBx(t *testing.T, errs ...error) *[]configure.MEBxOptions {
	t.Helper()

	var calls []configure.MEBxOptions

	orig := configureSetMEBx
	configureSetMEBx = func(opts configure.MEBxOptions) error {
		calls = append(calls, opts)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	t.Cleanup(func() { configureSetMEBx = orig })

	return &calls
}

// mebxOpts is the options struct the MEBx step for mebxProfile is expected to
// pass to pkg/configure.
func mebxOpts(amtPassword string, skipAMTCertCheck bool) configure.MEBxOptions {
	return configure.MEBxOptions{
		BaseOptions:  configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: skipAMTCertCheck},
		MEBxPassword: "mebx-pass",
	}
}

// mebxProfile is an ACM profile with an AdminPassword and a MEBx password.
func mebxProfile() config.Configuration {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = ACMMODE
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pass"
	cfg.Configuration.AMTSpecific.MEBXPassword = "mebx-pass"

	return cfg
}

func TestExecuteMEBxConfiguration_MapsOptions(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("skipAMTCertCheck=%t", skip), func(t *testing.T) {
			calls := stubSetMEBx(t)

			po := NewProfileOrchestrator(mebxProfile(), "", "cli-mebx", skip)
			po.currentControlMode = 2 // already in ACM
			po.globalPassword = "current-pass"

			require.NoError(t, po.executeMEBxConfiguration())

			// The profile's MEBx password wins; the CLI value only feeds activation.
			require.Equal(t, []configure.MEBxOptions{mebxOpts("current-pass", skip)}, *calls)
		})
	}
}

func TestExecuteMEBxConfiguration_SkipRules(t *testing.T) {
	tests := []struct {
		name        string
		controlMode int
		profile     func(*config.Configuration)
		wantLog     string
	}{
		{
			name:        "not ACM",
			controlMode: 2,
			profile: func(c *config.Configuration) {
				c.Configuration.AMTSpecific.ControlMode = "ccmactivate"
			},
			wantLog: "MEBx password not configured or not in ACM mode, skipping MEBx configuration",
		},
		{
			name:        "empty MEBx password",
			controlMode: 2,
			profile: func(c *config.Configuration) {
				c.Configuration.AMTSpecific.MEBXPassword = ""
			},
			wantLog: "MEBx password not configured or not in ACM mode, skipping MEBx configuration",
		},
		{
			name:        "pre-provisioning",
			controlMode: 0,
			wantLog:     "MEBx password was set during activation, skipping separate MEBx configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := captureLogs(t)
			calls := stubSetMEBx(t)

			cfg := mebxProfile()
			if tt.profile != nil {
				tt.profile(&cfg)
			}

			po := NewProfileOrchestrator(cfg, "", "", false)
			po.currentControlMode = tt.controlMode

			require.NoError(t, po.executeMEBxConfiguration())

			require.Empty(t, *calls)
			require.True(t, loggedMessage(hook, tt.wantLog), "the skip message must be logged")
		})
	}
}

func TestExecuteMEBxConfiguration_AuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubSetMEBx(t, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(mebxProfile(), "old-pass", "", true)
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.executeMEBxConfiguration())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", true)}, *rotations)
	require.Equal(t, []configure.MEBxOptions{
		mebxOpts("stale-pass", true),
		mebxOpts("admin-pass", true),
	}, *calls)
	require.Equal(t, "admin-pass", po.globalPassword)
}

func TestExecuteMEBxConfiguration_SettleRetry(t *testing.T) {
	t.Run("retries a plain error", func(t *testing.T) {
		calls := stubSetMEBx(t, errors.New("connection reset while AMT settles"))

		po := NewProfileOrchestrator(mebxProfile(), "", "", false)
		po.currentControlMode = 2
		po.globalPassword = "admin-pass"
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.executeMEBxConfiguration())

		require.Equal(t, []configure.MEBxOptions{
			mebxOpts("admin-pass", false),
			mebxOpts("admin-pass", false),
		}, *calls)
	})

	t.Run("stops on device not activated", func(t *testing.T) {
		calls := stubSetMEBx(t, utils.DeviceNotActivated, utils.DeviceNotActivated)

		po := NewProfileOrchestrator(mebxProfile(), "", "", false)
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.ErrorIs(t, po.executeMEBxConfiguration(), utils.DeviceNotActivated)

		require.Len(t, *calls, 1)
	})
}
