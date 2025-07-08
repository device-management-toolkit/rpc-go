/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	log "github.com/sirupsen/logrus"
)

// ActivateCmd represents the activate command with automatic mode detection
// Uses -u/--url for remote activation and -l/--local for explicit local activation
type ActivateCmd struct {
	// Mode selection flags
	Local bool   `help:"Force local activation mode" short:"l" name:"local"`
	URL   string `help:"RPS server URL (enables remote activation)" short:"u" name:"url"`

	// Remote activation flags
	Profile string `help:"Profile name to use for remote activation" name:"profile"`
	Proxy   string `help:"Proxy server URL for RPS connection" name:"proxy"`

	// Common flags (used by both local and remote)
	DNS          string `help:"DNS suffix override" short:"d" name:"dns"`
	Hostname     string `help:"Hostname override" name:"hostname"`
	FriendlyName string `help:"Friendly name to associate with this device" name:"name"`
	UUID         string `help:"UUID override (prevents MPS connection)" name:"uuid"`

	// Local activation flags
	CCM bool `help:"Activate in Client Control Mode" name:"ccm"`
	ACM bool `help:"Activate in Admin Control Mode" name:"acm"`

	// Local configuration flags that can be loaded from YAML
	Config              string `help:"Config file or SMB share URL" name:"config"`
	ConfigV2            string `help:"Config V2 file or SMB share URL" name:"configv2"`
	ConfigKey           string `help:"32 byte key to decrypt config file" env:"CONFIG_ENCRYPTION_KEY" name:"configencryptionkey"`
	AMTPassword         string `help:"AMT Password" env:"AMT_PASSWORD" name:"amtPassword"`
	ProvisioningCert    string `help:"Provisioning certificate (base64 encoded)" env:"PROVISIONING_CERT" name:"provisioningCert"`
	ProvisioningCertPwd string `help:"Provisioning certificate password" env:"PROVISIONING_CERT_PASSWORD" name:"provisioningCertPwd"`
	SkipIPRenew         bool   `help:"Skip DHCP renewal of IP address if AMT becomes enabled" name:"skipIPRenew"`
	StopConfig          bool   `help:"Transition AMT from in-provisioning to pre-provisioning state" name:"stopConfig"`
}

// Validate checks the command configuration and determines activation mode
func (cmd *ActivateCmd) Validate() error {
	// Check for conflicting mode specifications
	if cmd.Local && cmd.URL != "" {
		return fmt.Errorf("cannot specify both --local and --url flags")
	}

	// If URL is specified, it's remote mode - validate remote requirements
	if cmd.URL != "" {
		if cmd.Profile == "" {
			return fmt.Errorf("--profile is required for remote activation")
		}

		// Check for conflicting local-only flags
		if cmd.CCM {
			return fmt.Errorf("--ccm flag is only valid for local activation, not with --url")
		}

		if cmd.ACM {
			return fmt.Errorf("--acm flag is only valid for local activation, not with --url")
		}

		if cmd.StopConfig {
			return fmt.Errorf("--stopConfig flag is only valid for local activation, not with --url")
		}

		if cmd.Config != "" {
			return fmt.Errorf("--config flag is only valid for local activation, not with --url")
		}

		if cmd.ConfigV2 != "" {
			return fmt.Errorf("--configv2 flag is only valid for local activation, not with --url")
		}

		if cmd.ConfigKey != "" {
			return fmt.Errorf("--configencryptionkey flag is only valid for local activation, not with --url")
		}

		if cmd.AMTPassword != "" {
			return fmt.Errorf("--amtPassword flag is only valid for local activation, not with --url")
		}

		if cmd.ProvisioningCert != "" {
			return fmt.Errorf("--provisioningCert flag is only valid for local activation, not with --url")
		}

		if cmd.ProvisioningCertPwd != "" {
			return fmt.Errorf("--provisioningCertPwd flag is only valid for local activation, not with --url")
		}

		if cmd.SkipIPRenew {
			return fmt.Errorf("--skipIPRenew flag is only valid for local activation, not with --url")
		}

		// Warn about UUID override
		if cmd.UUID != "" {
			log.Warn("Overriding UUID prevents device from connecting to MPS")
		}

		return nil
	}

	// If --local is specified or local flags are present, it's local mode
	if cmd.Local || cmd.hasLocalActivationFlags() {
		// For local activation, validate mode selection unless stopConfig is used
		if !cmd.StopConfig && !cmd.CCM && !cmd.ACM {
			return fmt.Errorf("local activation requires either --ccm, --acm, or --stopConfig")
		}

		// CCM and ACM are mutually exclusive
		if cmd.CCM && cmd.ACM {
			return fmt.Errorf("cannot specify both --ccm and --acm")
		}

		return nil
	}

	// If no mode indicators are present, show help
	return fmt.Errorf("specify either --url for remote activation or --local/--ccm/--acm for local activation")
}

// hasLocalActivationFlags checks if any local-specific flags are set
func (cmd *ActivateCmd) hasLocalActivationFlags() bool {
	return cmd.CCM || cmd.ACM || cmd.StopConfig ||
		cmd.Config != "" || cmd.ConfigV2 != "" || cmd.ConfigKey != "" || cmd.AMTPassword != "" ||
		cmd.ProvisioningCert != "" || cmd.ProvisioningCertPwd != "" || cmd.SkipIPRenew
}

// Run executes the activate command based on detected mode
func (cmd *ActivateCmd) Run(ctx *commands.Context) error {
	// Determine activation mode based on flags
	if cmd.URL != "" {
		// Remote activation mode
		log.Debugf("Running remote activation with URL: %s", cmd.URL)

		return cmd.runRemoteActivation(ctx)
	}

	// Local activation mode (either explicit --local or local flags present)
	log.Debug("Running local activation")

	return cmd.runLocalActivation(ctx)
}

// runRemoteActivation executes remote activation using the remote service
func (cmd *ActivateCmd) runRemoteActivation(ctx *commands.Context) error {
	// Create remote activation command with current flags
	remoteCmd := RemoteActivateCmd{
		URL:          cmd.URL,
		Profile:      cmd.Profile,
		DNS:          cmd.DNS,
		Hostname:     cmd.Hostname,
		UUID:         cmd.UUID,
		FriendlyName: cmd.FriendlyName,
		Proxy:        cmd.Proxy,
	}

	// Validate and execute the remote command
	if err := remoteCmd.Validate(); err != nil {
		return err
	}

	return remoteCmd.Run(ctx)
}

// runLocalActivation executes local activation using the local service
func (cmd *ActivateCmd) runLocalActivation(ctx *commands.Context) error {
	// Create local activation command with current flags
	localCmd := LocalActivateCmd{
		LocalFlag:           cmd.Local, // Set for backwards compatibility
		CCM:                 cmd.CCM,
		ACM:                 cmd.ACM,
		DNS:                 cmd.DNS,
		Hostname:            cmd.Hostname,
		Config:              cmd.Config,
		ConfigV2:            cmd.ConfigV2,
		ConfigKey:           cmd.ConfigKey,
		AMTPassword:         cmd.AMTPassword,
		ProvisioningCert:    cmd.ProvisioningCert,
		ProvisioningCertPwd: cmd.ProvisioningCertPwd,
		FriendlyName:        cmd.FriendlyName,
		SkipIPRenew:         cmd.SkipIPRenew,
		StopConfig:          cmd.StopConfig,
	}

	// Validate and execute the local command
	if err := localCmd.Validate(); err != nil {
		return err
	}

	return localCmd.Run(ctx)
}
