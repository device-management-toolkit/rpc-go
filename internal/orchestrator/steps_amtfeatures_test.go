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

// stubSetAMTFeatures replaces configureSetAMTFeatures for the test. The stub
// records the options of every call and returns errs in order, then nil.
func stubSetAMTFeatures(t *testing.T, errs ...error) *[]configure.AMTFeaturesOptions {
	t.Helper()

	var calls []configure.AMTFeaturesOptions

	orig := configureSetAMTFeatures
	configureSetAMTFeatures = func(opts configure.AMTFeaturesOptions) error {
		calls = append(calls, opts)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	t.Cleanup(func() { configureSetAMTFeatures = orig })

	return &calls
}

// amtFeaturesProfile is an ACM profile with an AdminPassword, KVM and SOL
// enabled, IDER disabled and KVM-only user consent.
func amtFeaturesProfile() config.Configuration {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = ACMMODE
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pass"
	cfg.Configuration.Redirection.Services.KVM = true
	cfg.Configuration.Redirection.Services.SOL = true
	cfg.Configuration.Redirection.UserConsent = "KVM"

	return cfg
}

// amtFeaturesOpts is the options struct the AMT features step for
// amtFeaturesProfile is expected to pass to pkg/configure.
func amtFeaturesOpts(amtPassword string, skipAMTCertCheck bool) configure.AMTFeaturesOptions {
	return configure.AMTFeaturesOptions{
		BaseOptions: configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: skipAMTCertCheck},
		UserConsent: "kvm",
		KVM:         true,
		SOL:         true,
	}
}

func TestExecuteAMTFeaturesConfiguration_MapsOptions(t *testing.T) {
	base := func(skip bool) configure.BaseOptions {
		return configure.BaseOptions{AMTPassword: "current-pass", SkipAMTCertCheck: skip}
	}

	tests := []struct {
		name    string
		mode    string
		consent string
		kvm     bool
		sol     bool
		ider    bool
		want    func(skip bool) configure.AMTFeaturesOptions
	}{
		{
			name: "ACM all features, consent None", mode: ACMMODE, consent: "None", kvm: true, sol: true, ider: true,
			want: func(skip bool) configure.AMTFeaturesOptions {
				return configure.AMTFeaturesOptions{BaseOptions: base(skip), UserConsent: "none", KVM: true, SOL: true, IDER: true}
			},
		},
		{
			name: "ACM KVM only, consent KVM", mode: ACMMODE, consent: "KVM", kvm: true,
			want: func(skip bool) configure.AMTFeaturesOptions {
				return configure.AMTFeaturesOptions{BaseOptions: base(skip), UserConsent: "kvm", KVM: true}
			},
		},
		{
			name: "ACM SOL and IDER, consent All", mode: ACMMODE, consent: "All", sol: true, ider: true,
			want: func(skip bool) configure.AMTFeaturesOptions {
				return configure.AMTFeaturesOptions{BaseOptions: base(skip), UserConsent: "all", SOL: true, IDER: true}
			},
		},
		{
			name: "ACM empty consent maps to all", mode: ACMMODE, consent: "", kvm: true,
			want: func(skip bool) configure.AMTFeaturesOptions {
				return configure.AMTFeaturesOptions{BaseOptions: base(skip), UserConsent: "all", KVM: true}
			},
		},
		{
			name: "ACM unrecognized consent maps to all", mode: ACMMODE, consent: "Bogus", kvm: true,
			want: func(skip bool) configure.AMTFeaturesOptions {
				return configure.AMTFeaturesOptions{BaseOptions: base(skip), UserConsent: "all", KVM: true}
			},
		},
		{
			// CCM leaves UserConsent empty even when the profile sets one: the
			// old child got Kong's default "all" (internal/commands/configure/
			// amtfeatures.go, default:"all") and pkg SetAMTFeatures turns empty
			// into "all", so the effective consent is unchanged.
			name: "CCM ignores consent", mode: "ccmactivate", consent: "None", kvm: true, ider: true,
			want: func(skip bool) configure.AMTFeaturesOptions {
				return configure.AMTFeaturesOptions{BaseOptions: base(skip), KVM: true, IDER: true}
			},
		},
		{
			// The old step sent --disableAll here; pkg needs no such field
			// because its non-empty UserConsent default already passes Validate.
			name: "ACM all features off", mode: ACMMODE, consent: "None",
			want: func(skip bool) configure.AMTFeaturesOptions {
				return configure.AMTFeaturesOptions{BaseOptions: base(skip), UserConsent: "none"}
			},
		},
		{
			name: "CCM all features off", mode: "ccmactivate",
			want: func(skip bool) configure.AMTFeaturesOptions {
				return configure.AMTFeaturesOptions{BaseOptions: base(skip)}
			},
		},
	}

	for _, tt := range tests {
		for _, skip := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/skipAMTCertCheck=%t", tt.name, skip), func(t *testing.T) {
				calls := stubSetAMTFeatures(t)

				cfg := config.Configuration{}
				cfg.Configuration.AMTSpecific.ControlMode = tt.mode
				cfg.Configuration.Redirection.UserConsent = tt.consent
				cfg.Configuration.Redirection.Services.KVM = tt.kvm
				cfg.Configuration.Redirection.Services.SOL = tt.sol
				cfg.Configuration.Redirection.Services.IDER = tt.ider

				po := NewProfileOrchestrator(cfg, "", "", skip)
				executor := newMockExecutor()
				po.executor = executor
				po.currentControlMode = 2
				po.globalPassword = "current-pass"

				require.NoError(t, po.executeAMTFeaturesConfiguration())

				require.Equal(t, []configure.AMTFeaturesOptions{tt.want(skip)}, *calls)
				require.Equal(t, 0, executor.callCount, "the AMT features step must not run the CLI")
			})
		}
	}
}

func TestExecuteAMTFeaturesConfiguration_AlwaysRuns(t *testing.T) {
	// No skip rule: an empty profile still configures (disables) the features.
	hook := captureLogs(t)
	calls := stubSetAMTFeatures(t)

	po := NewProfileOrchestrator(config.Configuration{}, "", "", false)
	executor := newMockExecutor()
	po.executor = executor

	require.NoError(t, po.executeAMTFeaturesConfiguration())

	require.Len(t, *calls, 1)
	require.Equal(t, 0, executor.callCount)
	require.True(t, loggedMessage(hook, "Executing AMT features configuration"))
}

func TestExecuteAMTFeaturesConfiguration_AuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubSetAMTFeatures(t, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(amtFeaturesProfile(), "old-pass", "", true)
	executor := newMockExecutor()
	po.executor = executor
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.executeAMTFeaturesConfiguration())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", true)}, *rotations)
	require.Equal(t, []configure.AMTFeaturesOptions{
		amtFeaturesOpts("stale-pass", true),
		amtFeaturesOpts("admin-pass", true),
	}, *calls)
	require.Equal(t, "admin-pass", po.globalPassword)
	require.Equal(t, 0, executor.callCount, "rotation and retry must not run the CLI")
}

func TestExecuteAMTFeaturesConfiguration_SettleRetry(t *testing.T) {
	t.Run("retries a plain error", func(t *testing.T) {
		calls := stubSetAMTFeatures(t, errors.New("connection reset while AMT settles"))

		po := NewProfileOrchestrator(amtFeaturesProfile(), "", "", false)
		executor := newMockExecutor()
		po.executor = executor
		po.currentControlMode = 2
		po.globalPassword = "admin-pass"
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.executeAMTFeaturesConfiguration())

		require.Equal(t, []configure.AMTFeaturesOptions{
			amtFeaturesOpts("admin-pass", false),
			amtFeaturesOpts("admin-pass", false),
		}, *calls)
		require.Equal(t, 0, executor.callCount, "the settle retry must not run the CLI")
	})

	t.Run("stops on device not activated", func(t *testing.T) {
		calls := stubSetAMTFeatures(t, utils.DeviceNotActivated, utils.DeviceNotActivated)

		po := NewProfileOrchestrator(amtFeaturesProfile(), "", "", false)
		executor := newMockExecutor()
		po.executor = executor
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.ErrorIs(t, po.executeAMTFeaturesConfiguration(), utils.DeviceNotActivated)

		require.Len(t, *calls, 1)
		require.Equal(t, 0, executor.callCount, "the settle retry must not run the CLI")
	})
}
