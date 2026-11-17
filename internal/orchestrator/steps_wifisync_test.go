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

// stubConfigureWiFiSync replaces configureWiFiSync for the test. The stub
// records the options of every call and returns errs in order, then nil.
func stubConfigureWiFiSync(t *testing.T, errs ...error) *[]configure.WiFiSyncOptions {
	t.Helper()

	var calls []configure.WiFiSyncOptions

	orig := configureWiFiSync
	configureWiFiSync = func(opts configure.WiFiSyncOptions) error {
		calls = append(calls, opts)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	t.Cleanup(func() { configureWiFiSync = orig })

	return &calls
}

// wifiSyncProfile is an activated-device profile with an AdminPassword, OS
// WiFi sync on and UEFI WiFi sync off.
func wifiSyncProfile() config.Configuration {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pass"
	cfg.Configuration.Network.Wireless.WiFiSyncEnabled = true

	return cfg
}

// wifiSyncOpts is the options struct the wifisync step for wifiSyncProfile is
// expected to pass to pkg/configure.
func wifiSyncOpts(amtPassword string, skipAMTCertCheck bool) configure.WiFiSyncOptions {
	return configure.WiFiSyncOptions{
		BaseOptions: configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: skipAMTCertCheck},
		OSWiFiSync:  true,
	}
}

func TestExecuteEnableWiFi_MapsOptions(t *testing.T) {
	// The old step always sent both --oswifisync=<bool> and
	// --uefiwifisync=<bool>, so the CLI's default:"true" never applied and
	// false reaches pkg/configure as false.
	for _, osSync := range []bool{false, true} {
		for _, uefiSync := range []bool{false, true} {
			for _, skip := range []bool{false, true} {
				t.Run(fmt.Sprintf("os=%t/uefi=%t/skipAMTCertCheck=%t", osSync, uefiSync, skip), func(t *testing.T) {
					calls := stubConfigureWiFiSync(t)

					cfg := config.Configuration{}
					cfg.Configuration.Network.Wireless.WiFiSyncEnabled = osSync
					cfg.Configuration.Network.Wireless.UEFIWiFiSyncEnabled = uefiSync

					po := NewProfileOrchestrator(cfg, "", "", skip)
					po.currentControlMode = 2
					po.globalPassword = "current-pass"

					require.NoError(t, po.executeEnableWiFi())

					require.Equal(t, []configure.WiFiSyncOptions{{
						BaseOptions:  configure.BaseOptions{AMTPassword: "current-pass", SkipAMTCertCheck: skip},
						OSWiFiSync:   osSync,
						UEFIWiFiSync: uefiSync,
					}}, *calls)
				})
			}
		}
	}
}

func TestExecuteEnableWiFi_AlwaysRuns(t *testing.T) {
	// The step has no skip rule: an empty profile still syncs, with both
	// settings off.
	hook := captureLogs(t)
	calls := stubConfigureWiFiSync(t)

	po := NewProfileOrchestrator(config.Configuration{}, "", "", false)

	require.NoError(t, po.executeEnableWiFi())

	require.Equal(t, []configure.WiFiSyncOptions{{}}, *calls)
	require.True(t, loggedMessage(hook, "Executing WiFi sync configuration"))
}

func TestExecuteEnableWiFi_AuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubConfigureWiFiSync(t, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(wifiSyncProfile(), "old-pass", "", true)
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.executeEnableWiFi())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", true)}, *rotations)
	require.Equal(t, []configure.WiFiSyncOptions{
		wifiSyncOpts("stale-pass", true),
		wifiSyncOpts("admin-pass", true),
	}, *calls)
	require.Equal(t, "admin-pass", po.globalPassword)
}

func TestExecuteEnableWiFi_SettleRetry(t *testing.T) {
	t.Run("retries a plain error", func(t *testing.T) {
		calls := stubConfigureWiFiSync(t, errors.New("connection reset while AMT settles"))

		po := NewProfileOrchestrator(wifiSyncProfile(), "", "", false)
		po.currentControlMode = 2
		po.globalPassword = "admin-pass"
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.executeEnableWiFi())

		require.Equal(t, []configure.WiFiSyncOptions{
			wifiSyncOpts("admin-pass", false),
			wifiSyncOpts("admin-pass", false),
		}, *calls)
	})

	t.Run("stops on device not activated", func(t *testing.T) {
		calls := stubConfigureWiFiSync(t, utils.DeviceNotActivated, utils.DeviceNotActivated)

		po := NewProfileOrchestrator(wifiSyncProfile(), "", "", false)
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.ErrorIs(t, po.executeEnableWiFi(), utils.DeviceNotActivated)

		require.Len(t, *calls, 1)
	})
}
