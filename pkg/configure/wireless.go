/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// WirelessOptions configures WiFi settings on the AMT device.
type WirelessOptions struct {
	BaseOptions
	IEEE8021xProfileName            string
	IEEE8021xUsername               string
	IEEE8021xPassword               string
	IEEE8021xAuthenticationProtocol int
	IEEE8021xPrivateKey             string
	IEEE8021xClientCert             string
	IEEE8021xCACert                 string
	ProfileName                     string
	SSID                            string
	Priority                        int
	AuthenticationMethod            int
	EncryptionMethod                int
	PSKPassphrase                   string
	Purge                           bool
}

// ConfigureWireless configures WiFi settings on the AMT device.
func ConfigureWireless(opts WirelessOptions) error {
	cmd := &internalcfg.WirelessCmd{}
	cmd.IEEE8021xProfileName = opts.IEEE8021xProfileName
	cmd.IEEE8021xUsername = opts.IEEE8021xUsername
	cmd.IEEE8021xPassword = opts.IEEE8021xPassword
	cmd.IEEE8021xAuthenticationProtocol = opts.IEEE8021xAuthenticationProtocol
	cmd.IEEE8021xPrivateKey = opts.IEEE8021xPrivateKey
	cmd.IEEE8021xClientCert = opts.IEEE8021xClientCert
	cmd.IEEE8021xCACert = opts.IEEE8021xCACert
	cmd.ProfileName = opts.ProfileName
	cmd.SSID = opts.SSID
	cmd.Priority = opts.Priority
	cmd.AuthenticationMethod = opts.AuthenticationMethod
	cmd.EncryptionMethod = opts.EncryptionMethod
	cmd.PSKPassphrase = opts.PSKPassphrase
	cmd.Purge = opts.Purge

	return run(cmd, opts.BaseOptions)
}
