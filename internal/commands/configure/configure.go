/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
)

// ConfigureBaseCmd provides base functionality for all configure commands
type ConfigureBaseCmd struct {
	commands.AMTBaseCmd
}

// Validate currently performs no password prompting; password acquisition and
// WSMAN client setup are deferred to Run via EnsureRuntime to centralize
// prompting behavior after context construction.
func (cmd *ConfigureBaseCmd) Validate() error { return nil }

// EnsureRuntime performs the lazy initialization steps common to all configure
// subcommands: obtain AMT password (if required) and establish the WSMAN
// client. It should be called at the top of each Run method.
func (cmd *ConfigureBaseCmd) EnsureRuntime(ctx *commands.Context) error {
	if err := cmd.EnsureAMTPassword(ctx, cmd); err != nil {
		return err
	}

	return cmd.EnsureWSMAN(ctx)
}

// RequiresAMTPassword indicates whether this command requires AMT password
// For deactivate, password is required for both local and remote modes
func (cmd *ConfigureBaseCmd) RequiresAMTPassword() bool {
	// Password required for local mode or remote mode (when URL is provided)
	return true
}

// ConfigureCmd is the main configure command that contains all subcommands
type ConfigureCmd struct {
	MEBx           MEBxCmd         `cmd:"" name:"mebx" aliases:"setmebx" help:"Configure MEBx password"`
	AMTPassword    AMTPasswordCmd  `cmd:"" aliases:"amtpassword,changeamtpassword" help:"Change AMT password"`
	AMTFeatures    AMTFeaturesCmd  `cmd:"" aliases:"amtfeatures,setamtfeatures" help:"Configure AMT features (KVM, SOL, IDER, user consent)"`
	CIRA           CIRACmd         `cmd:"cira" help:"Configure Cloud-Initiated Remote Access (CIRA)"`
	SyncClock      SyncClockCmd    `cmd:"" aliases:"syncclock,synctime" help:"Synchronize host OS clock to AMT"`
	EnableWiFiSync EnableWifiCmd   `cmd:"" aliases:"enablewifisync,enablewifi" help:"Enable WiFi and local profile synchronization"`
	Wireless       WirelessCmd     `cmd:"" aliases:"wireless,wifi,addwifisettings" help:"Configure WiFi settings"`
	Wired          WiredCmd        `cmd:"" aliases:"wired,ethernet,addethernetsettings" help:"Configure wired ethernet settings"`
	TLS            TLSCmd          `cmd:"" aliases:"tls,configuretls" help:"Configure TLS settings"`
	Proxy          ProxyCmd        `cmd:"" aliases:"proxy,httpproxy" help:"Configure HTTP proxy access point for firmware-initiated connections"`
	Hostname       SyncHostnameCmd `cmd:"" aliases:"synchostname,sethostname" help:"Synchronize host OS hostname and DNS suffix to AMT general settings"`
}
