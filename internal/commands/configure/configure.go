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

// Validate implements Kong's Validate interface for configure commands
func (cmd *ConfigureBaseCmd) Validate() error {
	// Call base validation if password is required
	if cmd.RequiresAMTPassword() {
		if err := cmd.ValidatePasswordIfNeeded(cmd); err != nil {
			return err
		}
	}

	return nil
}

// RequiresAMTPassword indicates whether this command requires AMT password
// For deactivate, password is required for both local and remote modes
func (cmd *ConfigureBaseCmd) RequiresAMTPassword() bool {
	// Password required for local mode or remote mode (when URL is provided)
	return true
}

// ConfigureCmd is the main configure command that contains all subcommands
type ConfigureCmd struct {
	MEBx           MEBxCmd           `cmd:"" name:"mebx" aliases:"setmebx" help:"Configure MEBx password"`
	AMTPassword    AMTPasswordCmd    `cmd:"" aliases:"amtpassword,changeamtpassword" help:"Change AMT password"`
	AMTFeatures    AMTFeaturesCmd    `cmd:"" aliases:"amtfeatures,setamtfeatures" help:"Configure AMT features (KVM, SOL, IDER, user consent)"`
	CIRA           CIRACmd           `cmd:"cira" help:"Configure Cloud-Initiated Remote Access (CIRA)"`
	SyncClock      SyncClockCmd      `cmd:"" aliases:"syncclock,synctime" help:"Synchronize host OS clock to AMT"`
	EnableWiFiPort EnableWifiPortCmd `cmd:"" aliases:"enablewifiport,enablewifi" help:"Enable WiFi port and local profile synchronization"`
	Wireless       WirelessCmd       `cmd:"" aliases:"wireless,wifi,addwifisettings" help:"Configure WiFi settings"`
	Wired          WiredCmd          `cmd:"" aliases:"wired,ethernet,addethernetsettings" help:"Configure wired ethernet settings"`
	TLS            TLSCmd            `cmd:"" aliases:"tls,configuretls" help:"Configure TLS settings"`
	Proxy          ProxyCmd          `cmd:"" aliases:"proxy,httpproxy" help:"Configure HTTP proxy access point for firmware-initiated connections"`
}
