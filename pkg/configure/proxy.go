/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// ProxyOptions configures the HTTP proxy access point on the AMT device.
type ProxyOptions struct {
	BaseOptions
	// List shows existing HTTP proxy settings.
	List bool
	// Delete removes a proxy access point by address.
	Delete bool
	// Address is the proxy host or IP.
	Address string
	// Port is the proxy TCP port. Defaults to 80.
	Port int
	// NetworkDnsSuffix is the network DNS suffix for the access point.
	NetworkDnsSuffix string
}

// ConfigureProxy configures the HTTP proxy access point on the AMT device.
func ConfigureProxy(opts ProxyOptions) error {
	cmd := &internalcfg.ProxyCmd{}
	cmd.List = opts.List
	cmd.Delete = opts.Delete
	cmd.Address = opts.Address
	cmd.Port = opts.Port
	cmd.NetworkDnsSuffix = opts.NetworkDnsSuffix

	if cmd.Port == 0 {
		cmd.Port = 80
	}

	return run(cmd, opts.BaseOptions)
}
