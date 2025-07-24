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

	// 802.1x settings
	IEEE8021xProfileName            string `help:"802.1x profile name" name:"ieee8021xProfileName"`
	IEEE8021xUsername               string `help:"802.1x username" alias:"username" name:"ieee8021xUsername"`
	IEEE8021xPassword               string `help:"802.1x password" name:"ieee8021xPassword"`
	IEEE8021xAuthenticationProtocol int    `help:"802.1x authentication protocol (0=EAP-TLS, 2=PEAPv0/EAP-MSCHAPv2)" alias:"authenticationprotocol" enum:"0,2" default:"0" name:"ieee8021xAuthenticationProtocol"`
	IEEE8021xPrivateKey             string `help:"802.1x private key (PEM format)" alias:"privatekey" name:"ieee8021xPrivateKey"`
	IEEE8021xClientCert             string `help:"802.1x client certificate (PEM format)" alias:"clientcert" name:"ieee8021xClientCert"`
	IEEE8021xCACert                 string `help:"802.1x CA certificate (PEM format)" alias:"cacert" name:"ieee8021xCACert"`

	// Enterprise Assistant settings
	EAAddress  string `help:"Enterprise Assistant address" name:"eaAddress"`
	EAUsername string `help:"Enterprise Assistant username" name:"eaUsername"`
	EAPassword string `help:"Enterprise Assistant password" name:"eaPassword"`
}

// Validate implements Kong's Validate interface for configure commands
func (cmd *ConfigureBaseCmd) Validate() error {
	// Call base validation if password is required
	if cmd.RequiresAMTPassword() {
		if err := cmd.AMTBaseCmd.ValidatePasswordIfNeeded(cmd); err != nil {
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
}
