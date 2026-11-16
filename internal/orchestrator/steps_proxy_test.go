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

// stubConfigureProxy replaces configureProxy for the test. The stub records
// the options of every call and returns errs in order, then nil.
func stubConfigureProxy(t *testing.T, errs ...error) *[]configure.ProxyOptions {
	t.Helper()

	var calls []configure.ProxyOptions

	orig := configureProxy
	configureProxy = func(opts configure.ProxyOptions) error {
		calls = append(calls, opts)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	t.Cleanup(func() { configureProxy = orig })

	return &calls
}

// proxyProfile is an activated-device profile with an AdminPassword and one
// HTTP proxy.
func proxyProfile() config.Configuration {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pass"
	cfg.Configuration.Network.Proxies = []config.Proxy{{Address: "proxy.example.com", Port: 8080}}

	return cfg
}

// proxyOpts is the options struct the proxy step for proxyProfile is expected
// to pass to pkg/configure.
func proxyOpts(amtPassword string, skipAMTCertCheck bool) configure.ProxyOptions {
	return configure.ProxyOptions{
		BaseOptions: configure.BaseOptions{AMTPassword: amtPassword, SkipAMTCertCheck: skipAMTCertCheck},
		Address:     "proxy.example.com",
		Port:        8080,
	}
}

func TestExecuteHTTPProxyConfiguration_MapsOptions(t *testing.T) {
	// Port maps only when > 0; otherwise it stays 0 and pkg/configure applies
	// the CLI default of 80 the old child got when --port was omitted.
	tests := []struct {
		name  string
		proxy config.Proxy
		want  configure.ProxyOptions
	}{
		{
			name:  "address only",
			proxy: config.Proxy{Address: "proxy.example.com"},
			want:  configure.ProxyOptions{Address: "proxy.example.com"},
		},
		{
			name:  "port 8080",
			proxy: config.Proxy{Address: "proxy.example.com", Port: 8080},
			want:  configure.ProxyOptions{Address: "proxy.example.com", Port: 8080},
		},
		{
			name:  "port 0 stays 0",
			proxy: config.Proxy{Address: "proxy.example.com", Port: 0},
			want:  configure.ProxyOptions{Address: "proxy.example.com"},
		},
		{
			name:  "negative port maps to 0",
			proxy: config.Proxy{Address: "proxy.example.com", Port: -5},
			want:  configure.ProxyOptions{Address: "proxy.example.com"},
		},
		{
			name:  "network DNS suffix",
			proxy: config.Proxy{Address: "10.0.0.1", Port: 3128, NetworkDnsSuffix: "corp.example.com"},
			want:  configure.ProxyOptions{Address: "10.0.0.1", Port: 3128, NetworkDnsSuffix: "corp.example.com"},
		},
	}

	for _, tt := range tests {
		for _, skip := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/skipAMTCertCheck=%t", tt.name, skip), func(t *testing.T) {
				calls := stubConfigureProxy(t)

				cfg := proxyProfile()
				cfg.Configuration.Network.Proxies = []config.Proxy{tt.proxy}

				po := NewProfileOrchestrator(cfg, "", "", skip)
				po.currentControlMode = 2
				po.globalPassword = "current-pass"

				require.NoError(t, po.executeHTTPProxyConfiguration())

				want := tt.want
				want.BaseOptions = configure.BaseOptions{AMTPassword: "current-pass", SkipAMTCertCheck: skip}

				require.Equal(t, []configure.ProxyOptions{want}, *calls)
			})
		}
	}
}

func TestExecuteHTTPProxyConfiguration_OneCallPerProxy(t *testing.T) {
	twoProxies := func() config.Configuration {
		cfg := proxyProfile()
		cfg.Configuration.Network.Proxies = []config.Proxy{
			{Address: "first.example.com", Port: 8080},
			{Address: "second.example.com", NetworkDnsSuffix: "corp.example.com"},
		}

		return cfg
	}

	base := configure.BaseOptions{AMTPassword: "current-pass"}

	t.Run("calls in profile order", func(t *testing.T) {
		calls := stubConfigureProxy(t)

		po := NewProfileOrchestrator(twoProxies(), "", "", false)
		po.currentControlMode = 2
		po.globalPassword = "current-pass"

		require.NoError(t, po.executeHTTPProxyConfiguration())

		require.Equal(t, []configure.ProxyOptions{
			{BaseOptions: base, Address: "first.example.com", Port: 8080},
			{BaseOptions: base, Address: "second.example.com", NetworkDnsSuffix: "corp.example.com"},
		}, *calls)
	})

	t.Run("failure on the first stops the loop", func(t *testing.T) {
		stepErr := errors.New("proxy rejected")
		calls := stubConfigureProxy(t, stepErr)

		po := NewProfileOrchestrator(twoProxies(), "", "", false)
		po.currentControlMode = 2
		po.globalPassword = "current-pass"

		err := po.executeHTTPProxyConfiguration()
		require.ErrorIs(t, err, stepErr)
		require.EqualError(t, err, "failed to configure HTTP proxy first.example.com: proxy rejected")

		require.Equal(t, []configure.ProxyOptions{
			{BaseOptions: base, Address: "first.example.com", Port: 8080},
		}, *calls)
	})
}

func TestExecuteHTTPProxyConfiguration_SkipsWhenNotConfigured(t *testing.T) {
	for _, proxies := range [][]config.Proxy{nil, {}} {
		t.Run(fmt.Sprintf("proxies=%#v", proxies), func(t *testing.T) {
			hook := captureLogs(t)
			calls := stubConfigureProxy(t)

			cfg := proxyProfile()
			cfg.Configuration.Network.Proxies = proxies

			po := NewProfileOrchestrator(cfg, "pwd", "", false)

			require.NoError(t, po.executeHTTPProxyConfiguration())

			require.Empty(t, *calls)
			require.True(t, loggedMessage(hook, "No HTTP proxy configurations specified, skipping"))
		})
	}
}

func TestExecuteHTTPProxyConfiguration_AuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubConfigureProxy(t, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(proxyProfile(), "old-pass", "", true)
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.executeHTTPProxyConfiguration())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", true)}, *rotations)
	require.Equal(t, []configure.ProxyOptions{
		proxyOpts("stale-pass", true),
		proxyOpts("admin-pass", true),
	}, *calls)
	require.Equal(t, "admin-pass", po.globalPassword)
}

func TestExecuteHTTPProxyConfiguration_SettleRetry(t *testing.T) {
	t.Run("retries a plain error", func(t *testing.T) {
		calls := stubConfigureProxy(t, errors.New("connection reset while AMT settles"))

		po := NewProfileOrchestrator(proxyProfile(), "", "", false)
		po.currentControlMode = 2
		po.globalPassword = "admin-pass"
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.executeHTTPProxyConfiguration())

		require.Equal(t, []configure.ProxyOptions{
			proxyOpts("admin-pass", false),
			proxyOpts("admin-pass", false),
		}, *calls)
	})

	t.Run("stops on device not activated", func(t *testing.T) {
		calls := stubConfigureProxy(t, utils.DeviceNotActivated, utils.DeviceNotActivated)

		po := NewProfileOrchestrator(proxyProfile(), "", "", false)
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.ErrorIs(t, po.executeHTTPProxyConfiguration(), utils.DeviceNotActivated)

		require.Len(t, *calls, 1)
	})
}
