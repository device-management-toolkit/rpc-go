/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package maintenance

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// SyncIPCmd maps legacy maintenance syncip to configure wired semantics
type SyncIPCmd struct {
	configure.ConfigureBaseCmd

	// Flags mimic the legacy maintenance flags but align to wired config
	StaticIP     string `help:"Static IP address (optional)" name:"staticip"`
	Netmask      string `help:"Subnet mask (optional)" name:"netmask"`
	Gateway      string `help:"Default gateway (optional)" name:"gateway"`
	PrimaryDNS   string `help:"Primary DNS (optional)" name:"primarydns"`
	SecondaryDNS string `help:"Secondary DNS (optional)" name:"secondarydns"`
}

func (cmd *SyncIPCmd) Validate() error {
	return cmd.ConfigureBaseCmd.Validate()
}

func (cmd *SyncIPCmd) Run(ctx *commands.Context) error {
	// Reuse wired command
	wired := &configure.WiredCmd{}
	wired.ConfigureBaseCmd = cmd.ConfigureBaseCmd

	// If no static values provided, default to IP Sync (host OS)
	if cmd.StaticIP == "" && cmd.Netmask == "" && cmd.Gateway == "" && cmd.PrimaryDNS == "" && cmd.SecondaryDNS == "" {
		wired.IPSyncEnabled = true
	} else {
		// Static mode
		wired.IPAddress = cmd.StaticIP
		wired.SubnetMask = cmd.Netmask
		wired.Gateway = cmd.Gateway
		wired.PrimaryDNS = cmd.PrimaryDNS
		wired.SecondaryDNS = cmd.SecondaryDNS
	}

	if err := wired.Validate(); err != nil {
		return fmt.Errorf("invalid syncip parameters: %w", err)
	}

	return wired.Run(ctx)
}
