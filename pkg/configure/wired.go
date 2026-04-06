/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// WiredOptions configures wired ethernet settings on the AMT device.
type WiredOptions struct {
	BaseOptions
	IEEE8021xProfileName            string
	IEEE8021xUsername               string
	IEEE8021xPassword               string
	IEEE8021xAuthenticationProtocol int
	IEEE8021xPrivateKey             string
	IEEE8021xClientCert             string
	IEEE8021xCACert                 string
	EAAddress                       string
	EAUsername                      string
	EAPassword                      string
	DHCPEnabled                     *bool
	IPSyncEnabled                   bool
	IPAddress                       string
	SubnetMask                      string
	Gateway                         string
	PrimaryDNS                      string
	SecondaryDNS                    string
}

// ConfigureWired configures wired ethernet settings on the AMT device.
func ConfigureWired(opts WiredOptions) error {
	cmd := &internalcfg.WiredCmd{}
	cmd.IEEE8021xProfileName = opts.IEEE8021xProfileName
	cmd.IEEE8021xUsername = opts.IEEE8021xUsername
	cmd.IEEE8021xPassword = opts.IEEE8021xPassword
	cmd.IEEE8021xAuthenticationProtocol = opts.IEEE8021xAuthenticationProtocol
	cmd.IEEE8021xPrivateKey = opts.IEEE8021xPrivateKey
	cmd.IEEE8021xClientCert = opts.IEEE8021xClientCert
	cmd.IEEE8021xCACert = opts.IEEE8021xCACert
	cmd.EAAddress = opts.EAAddress
	cmd.EAUsername = opts.EAUsername
	cmd.EAPassword = opts.EAPassword
	cmd.DHCPEnabled = opts.DHCPEnabled
	cmd.IPSyncEnabled = opts.IPSyncEnabled
	cmd.IPAddress = opts.IPAddress
	cmd.SubnetMask = opts.SubnetMask
	cmd.Gateway = opts.Gateway
	cmd.PrimaryDNS = opts.PrimaryDNS
	cmd.SecondaryDNS = opts.SecondaryDNS

	return run(cmd, opts.BaseOptions)
}
