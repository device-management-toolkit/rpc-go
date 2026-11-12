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

// stubConfigureWired replaces configureWired for the test. The stub records
// the options of every call and returns errs in order, then nil.
func stubConfigureWired(t *testing.T, errs ...error) *[]configure.WiredOptions {
	t.Helper()

	var calls []configure.WiredOptions

	orig := configureWired
	configureWired = func(opts configure.WiredOptions) error {
		calls = append(calls, opts)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	t.Cleanup(func() { configureWired = orig })

	return &calls
}

// wiredProfile is an activated-device profile with an AdminPassword and DHCP
// wired networking.
func wiredProfile() config.Configuration {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pass"
	cfg.Configuration.Network.Wired.DHCPEnabled = true

	return cfg
}

// wiredOpts is the options struct the wired step for wiredProfile is expected
// to pass to pkg/configure.
func wiredOpts(amtPassword string, skipAMTCertCheck bool) configure.WiredOptions {
	dhcp := true

	return configure.WiredOptions{
		BaseOptions: configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: skipAMTCertCheck},
		DHCPEnabled: &dhcp,
	}
}

func TestExecuteWiredNetworkConfiguration_MapsOptions(t *testing.T) {
	base := func(skip bool) configure.BaseOptions {
		return configure.BaseOptions{AMTPassword: "current-pass", SkipAMTCertCheck: skip}
	}

	dhcp := true

	// The old step sent only --dhcp, or the non-empty static flags. It never
	// sent --ipsync, 802.1x or EA flags, so those fields stay zero.
	tests := []struct {
		name  string
		wired config.Wired
		want  func(skip bool) configure.WiredOptions
	}{
		{
			name:  "DHCP",
			wired: config.Wired{DHCPEnabled: true},
			want: func(skip bool) configure.WiredOptions {
				return configure.WiredOptions{BaseOptions: base(skip), DHCPEnabled: &dhcp}
			},
		},
		{
			// DHCP wins: the old step sent only --dhcp and ignored the
			// static fields, the IP sync flag and any 802.1x profile.
			name: "DHCP ignores static, IP sync and 802.1x fields",
			wired: config.Wired{
				DHCPEnabled: true, IPSyncEnabled: true, IPAddress: "192.168.1.10", SubnetMask: "255.255.255.0",
				DefaultGateway: "192.168.1.1", PrimaryDNS: "8.8.8.8", SecondaryDNS: "8.8.4.4",
				SharedStaticIP: true, Authentication: "8021x",
				IEEE8021x: &config.IEEE8021x{Username: "user", Password: "secret", AuthenticationProtocol: 2},
			},
			want: func(skip bool) configure.WiredOptions {
				return configure.WiredOptions{BaseOptions: base(skip), DHCPEnabled: &dhcp}
			},
		},
		{
			// IP sync and 802.1x stay unmapped for static profiles as well.
			name: "static, all fields",
			wired: config.Wired{
				IPSyncEnabled: true, IPAddress: "192.168.1.10", SubnetMask: "255.255.255.0", DefaultGateway: "192.168.1.1",
				PrimaryDNS: "8.8.8.8", SecondaryDNS: "8.8.4.4",
				IEEE8021x: &config.IEEE8021x{Username: "user", Password: "secret", AuthenticationProtocol: 2},
			},
			want: func(skip bool) configure.WiredOptions {
				return configure.WiredOptions{
					BaseOptions: base(skip), IPAddress: "192.168.1.10", SubnetMask: "255.255.255.0",
					Gateway: "192.168.1.1", PrimaryDNS: "8.8.8.8", SecondaryDNS: "8.8.4.4",
				}
			},
		},
		{
			name:  "static, address and mask only",
			wired: config.Wired{IPAddress: "10.0.0.5", SubnetMask: "255.0.0.0"},
			want: func(skip bool) configure.WiredOptions {
				return configure.WiredOptions{BaseOptions: base(skip), IPAddress: "10.0.0.5", SubnetMask: "255.0.0.0"}
			},
		},
		{
			name:  "static, DNS only",
			wired: config.Wired{PrimaryDNS: "1.1.1.1"},
			want: func(skip bool) configure.WiredOptions {
				return configure.WiredOptions{BaseOptions: base(skip), PrimaryDNS: "1.1.1.1"}
			},
		},
		{
			name:  "static, secondary DNS only",
			wired: config.Wired{SecondaryDNS: "1.0.0.1"},
			want: func(skip bool) configure.WiredOptions {
				return configure.WiredOptions{BaseOptions: base(skip), SecondaryDNS: "1.0.0.1"}
			},
		},
	}

	for _, tt := range tests {
		for _, skip := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/skipAMTCertCheck=%t", tt.name, skip), func(t *testing.T) {
				calls := stubConfigureWired(t)

				cfg := config.Configuration{}
				cfg.Configuration.Network.Wired = tt.wired

				po := NewProfileOrchestrator(cfg, "", "", skip)
				executor := newMockExecutor()
				po.executor = executor
				po.currentControlMode = 2
				po.globalPassword = "current-pass"

				require.NoError(t, po.executeWiredNetworkConfiguration())

				require.Equal(t, []configure.WiredOptions{tt.want(skip)}, *calls)
				require.Equal(t, 0, executor.callCount, "the wired step must not run the CLI")
			})
		}
	}
}

func TestExecuteWiredNetworkConfiguration_Skips(t *testing.T) {
	tests := []struct {
		name  string
		wired config.Wired
	}{
		{name: "empty profile"},
		{
			// Mask and gateway alone do not trigger the step.
			name:  "mask and gateway without address, DHCP or DNS",
			wired: config.Wired{SubnetMask: "255.255.255.0", DefaultGateway: "192.168.1.1", IPSyncEnabled: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hook := captureLogs(t)
			calls := stubConfigureWired(t)

			cfg := config.Configuration{}
			cfg.Configuration.Network.Wired = tt.wired

			po := NewProfileOrchestrator(cfg, "", "", false)
			executor := newMockExecutor()
			po.executor = executor

			require.NoError(t, po.executeWiredNetworkConfiguration())

			require.Empty(t, *calls)
			require.Equal(t, 0, executor.callCount)
			require.True(t, loggedMessage(hook, "No wired network configuration specified, skipping"))
		})
	}
}

func TestExecuteWiredNetworkConfiguration_AuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubConfigureWired(t, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(wiredProfile(), "old-pass", "", true)
	executor := newMockExecutor()
	po.executor = executor
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.executeWiredNetworkConfiguration())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", true)}, *rotations)
	require.Equal(t, []configure.WiredOptions{
		wiredOpts("stale-pass", true),
		wiredOpts("admin-pass", true),
	}, *calls)
	require.Equal(t, "admin-pass", po.globalPassword)
	require.Equal(t, 0, executor.callCount, "rotation and retry must not run the CLI")
}

func TestExecuteWiredNetworkConfiguration_SettleRetry(t *testing.T) {
	t.Run("retries a plain error", func(t *testing.T) {
		calls := stubConfigureWired(t, errors.New("connection reset while AMT settles"))

		po := NewProfileOrchestrator(wiredProfile(), "", "", false)
		executor := newMockExecutor()
		po.executor = executor
		po.currentControlMode = 2
		po.globalPassword = "admin-pass"
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.executeWiredNetworkConfiguration())

		require.Equal(t, []configure.WiredOptions{
			wiredOpts("admin-pass", false),
			wiredOpts("admin-pass", false),
		}, *calls)
		require.Equal(t, 0, executor.callCount, "the settle retry must not run the CLI")
	})

	t.Run("stops on device not activated", func(t *testing.T) {
		calls := stubConfigureWired(t, utils.DeviceNotActivated, utils.DeviceNotActivated)

		po := NewProfileOrchestrator(wiredProfile(), "", "", false)
		executor := newMockExecutor()
		po.executor = executor
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.ErrorIs(t, po.executeWiredNetworkConfiguration(), utils.DeviceNotActivated)

		require.Len(t, *calls, 1)
		require.Equal(t, 0, executor.callCount, "the settle retry must not run the CLI")
	})
}
