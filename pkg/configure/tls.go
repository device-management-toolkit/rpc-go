/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// TLSOptions configures TLS settings on the AMT device.
type TLSOptions struct {
	BaseOptions
	// EAAddress is the Enterprise Assistant address (optional).
	EAAddress string
	// EAUsername is the Enterprise Assistant username.
	EAUsername string
	// EAPassword is the Enterprise Assistant password.
	EAPassword string
	// Mode is the TLS authentication mode.
	// Valid values: "Server", "ServerAndNonTLS", "Mutual", "MutualAndNonTLS", "None".
	// Defaults to "Server" if empty.
	Mode string
	// Delay is the pause in seconds after applying remote TLS settings. Defaults to 3.
	Delay int
}

// ConfigureTLS configures TLS settings on the AMT device.
func ConfigureTLS(opts TLSOptions) error {
	cmd := &internalcfg.TLSCmd{}
	cmd.EAAddress = opts.EAAddress
	cmd.EAUsername = opts.EAUsername
	cmd.EAPassword = opts.EAPassword
	cmd.Mode = opts.Mode
	cmd.Delay = opts.Delay

	if cmd.Mode == "" {
		cmd.Mode = "Server"
	}

	if cmd.Delay == 0 {
		cmd.Delay = 3
	}

	return run(cmd, opts.BaseOptions)
}
