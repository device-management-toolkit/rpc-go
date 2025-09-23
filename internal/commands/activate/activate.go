/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/security"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/orchestrator"
	"github.com/device-management-toolkit/rpc-go/v2/internal/profile"

	log "github.com/sirupsen/logrus"
)

// ActivateCmd represents the activate command with automatic mode detection
// Uses -u/--url for remote activation and -l/--local for explicit local activation
type ActivateCmd struct {
	commands.AMTBaseCmd

	// Mode selection flags
	Local bool   `help:"Force local activation mode" short:"l" name:"local"`
	URL   string `help:"RPS server URL (enables remote activation)" short:"u" name:"url"`

	// Remote activation flags
	Profile string `help:"Profile name to use for legacy remote activation (wss/ws). For local/HTTP profiles, pass a file path instead." name:"profile"`
	Proxy   string `help:"Proxy server URL for RPS connection (legacy remote)" name:"proxy"`

	// HTTP profile fetch auth flags are provided via embedded ServerAuthFlags (includes auth-endpoint)

	// Optional decryption key for local or HTTP-delivered encrypted profile content
	Key string `help:"32 byte key to decrypt profile (local file or raw HTTP body)" short:"k" name:"key" env:"CONFIG_ENCRYPTION_KEY"`

	// Common flags (used by both local and remote)
	DNS          string `help:"DNS suffix override" short:"d" name:"dns"`
	Hostname     string `help:"Hostname override" name:"hostname"`
	FriendlyName string `help:"Friendly name to associate with this device" name:"name"`
	UUID         string `help:"UUID override (prevents MPS connection)" name:"uuid"`

	// Local activation flags
	CCM bool `help:"Activate in Client Control Mode" name:"ccm"`
	ACM bool `help:"Activate in Admin Control Mode" name:"acm"`

	// Local configuration flags that can be loaded from YAML
	ProvisioningCert    string `help:"Provisioning certificate (base64 encoded)" env:"PROVISIONING_CERT" name:"provisioningCert"`
	ProvisioningCertPwd string `help:"Provisioning certificate password" env:"PROVISIONING_CERT_PASSWORD" name:"provisioningCertPwd"`
	SkipIPRenew         bool   `help:"Skip DHCP renewal of IP address if AMT becomes enabled" name:"skipIPRenew"`
	StopConfig          bool   `help:"Transition AMT from in-provisioning to pre-provisioning state" name:"stopConfig"`

	// Shared server authentication flags for remote flows (optional)
	commands.ServerAuthFlags
}

// RequiresAMTPassword indicates whether this command requires AMT password
// For activate, password is required for local activation (to set the AMT password).
// The stopConfig path does not require an AMT password.
func (cmd *ActivateCmd) RequiresAMTPassword() bool {
	return !cmd.StopConfig
}

// Validate checks the command configuration and determines activation mode
func (cmd *ActivateCmd) Validate() error {
	// Check for conflicting mode specifications
	if cmd.Local && cmd.URL != "" {
		return fmt.Errorf("cannot specify both --local and --url flags")
	}

	// If URL is specified, split behavior by scheme
	if cmd.URL != "" {
		if strings.HasPrefix(strings.ToLower(cmd.URL), "ws://") || strings.HasPrefix(strings.ToLower(cmd.URL), "wss://") {
			// Legacy remote activation via RPS requires profile name
			if cmd.Profile == "" {
				return fmt.Errorf("--profile is required for remote activation with ws/wss URLs")
			}

			// Disallow local/HTTP-only flags with legacy messages for tests
			if cmd.CCM {
				return fmt.Errorf("--ccm flag is only valid for local activation, not with --url")
			}

			if cmd.ACM {
				return fmt.Errorf("--acm flag is only valid for local activation, not with --url")
			}

			if cmd.StopConfig {
				return fmt.Errorf("--stopConfig flag is only valid for local activation, not with --url")
			}

			if cmd.GetPassword() != "" {
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

			if cmd.AuthToken != "" || cmd.AuthUsername != "" || cmd.AuthPassword != "" || cmd.Key != "" {
				return fmt.Errorf("HTTP auth/decryption flags are not valid with ws/wss --url")
			}

			// Warn about UUID override
			if cmd.UUID != "" {
				log.Warn("Overriding UUID prevents device from connecting to MPS")
			}

			return nil
		}

		if strings.HasPrefix(strings.ToLower(cmd.URL), "http://") || strings.HasPrefix(strings.ToLower(cmd.URL), "https://") {
			// HTTP profile fetch fullflow. Disallow local-only flags
			if cmd.CCM || cmd.ACM {
				return fmt.Errorf("local activation flags are not valid with HTTP(S) --url")
			}
			// Do not require --profile for HTTP(S)
			return nil
		}

		return fmt.Errorf("unsupported url scheme: %s", cmd.URL)
	}

	// If --profile is a file path (local fullflow)
	if cmd.Profile != "" {
		if looksLikeFilePath(cmd.Profile) {
			// Disallow local activation flags that conflict; orchestrator uses profile
			if cmd.CCM || cmd.ACM || cmd.StopConfig {
				return fmt.Errorf("--ccm/--acm/--stopConfig are not valid when --profile points to a file")
			}

			if cmd.URL != "" {
				return fmt.Errorf("cannot combine file --profile with --url")
			}

			return nil
		}

		// Otherwise treat as legacy profile name; require ws/wss URL
		if cmd.URL == "" {
			return fmt.Errorf("--profile as a name requires --url with ws/wss scheme")
		}
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

		// Prompt for AMT password when required for local activation
		if cmd.RequiresAMTPassword() {
			if err := cmd.ValidatePasswordIfNeeded(cmd); err != nil {
				return err
			}
		}

		return nil
	}

	// If no mode indicators are present, show help
	return fmt.Errorf("specify either --url for remote activation or --local/--ccm/--acm for local activation")
}

// hasLocalActivationFlags checks if any local-specific flags are set
func (cmd *ActivateCmd) hasLocalActivationFlags() bool {
	return cmd.CCM || cmd.ACM || cmd.StopConfig ||
		cmd.GetPassword() != "" || cmd.ProvisioningCert != "" || cmd.ProvisioningCertPwd != "" || cmd.SkipIPRenew
}

// Run executes the activate command based on detected mode
func (cmd *ActivateCmd) Run(ctx *commands.Context) error {
	// Determine activation mode based on flags
	if cmd.URL != "" {
		// Remote URL provided: choose path by scheme
		lower := strings.ToLower(cmd.URL)
		if strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
			log.Debugf("Running legacy remote activation with URL: %s", cmd.URL)

			return cmd.runRemoteActivation(ctx)
		}

		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			log.Debugf("Running HTTP(S) profile fullflow from URL: %s", cmd.URL)

			return cmd.runHttpProfileFullflow(ctx)
		}

		return fmt.Errorf("unsupported url scheme: %s", cmd.URL)
	}

	// If profile looks like a file path, run local file fullflow
	if cmd.Profile != "" && looksLikeFilePath(cmd.Profile) {
		log.Debugf("Running local profile fullflow from file: %s", cmd.Profile)

		return cmd.runLocalProfileFullflow()
	}

	// Local activation mode (either explicit --local or local flags present)
	log.Debug("Running local activation")

	return cmd.runLocalActivation(ctx)
}

// runRemoteActivation executes remote activation using the remote service
func (cmd *ActivateCmd) runRemoteActivation(ctx *commands.Context) error {
	// Create remote activation command with current flags
	remoteCmd := RemoteActivateCmd{
		URL:             cmd.URL,
		Profile:         cmd.Profile,
		DNS:             cmd.DNS,
		Hostname:        cmd.Hostname,
		UUID:            cmd.UUID,
		FriendlyName:    cmd.FriendlyName,
		Proxy:           cmd.Proxy,
		ServerAuthFlags: cmd.ServerAuthFlags,
	}

	// Validate and execute the remote command
	if err := remoteCmd.Validate(); err != nil {
		return err
	}

	return remoteCmd.Run(ctx)
}

// runHttpProfileFullflow fetches a profile over HTTP(S) and runs the orchestrator
func (cmd *ActivateCmd) runHttpProfileFullflow(ctx *commands.Context) error {
	// Reuse ProfileFetcher
	fetcher := &profile.ProfileFetcher{
		URL:           cmd.URL,
		Token:         cmd.AuthToken,
		Username:      cmd.AuthUsername,
		Password:      cmd.AuthPassword,
		AuthEndpoint:  cmd.AuthEndpoint,
		SkipCertCheck: ctx.SkipCertCheck,
	}
	// Allow client-provided key for HTTP bodies or envelopes missing key
	if cmd.Key != "" {
		fetcher.ClientKey = cmd.Key
	}

	cfg, err := fetcher.FetchProfile()
	if err != nil {
		return fmt.Errorf("failed to fetch profile: %w", err)
	}

	orch := orchestrator.NewProfileOrchestrator(cfg)
	if err := orch.ExecuteProfile(); err != nil {
		return err
	}

	log.Info("Profile fullflow completed successfully")

	return nil
}

// runLocalProfileFullflow loads a local profile file (optionally decrypt) and runs the orchestrator
func (cmd *ActivateCmd) runLocalProfileFullflow() error {
	// Prefer existing loader for plaintext YAML
	if cmd.Key == "" {
		c, err := profile.LoadProfile(cmd.Profile)
		if err != nil {
			return fmt.Errorf("failed to load profile: %w", err)
		}

		orch := orchestrator.NewProfileOrchestrator(c)
		if err := orch.ExecuteProfile(); err != nil {
			return err
		}

		log.Info("Profile fullflow completed successfully")

		return nil
	}

	// Encrypted file path handling using go-wsman security helper
	return cmd.runLocalEncryptedProfile()
}

// looksLikeFilePath determines if the provided string looks like a file path (absolute, relative, UNC, or has an extension)
func looksLikeFilePath(p string) bool {
	if p == "" {
		return false
	}
	// UNC path or drive letter or contains path separators
	lower := strings.ToLower(p)
	if strings.HasPrefix(lower, `\\`) || strings.ContainsAny(p, `/\\`) {
		return true
	}
	// Has a known profile extension
	ext := strings.ToLower(filepath.Ext(p))
	switch ext {
	case ".yaml", ".yml", ".json", ".enc", ".bin":
		return true
	}

	return false
}

// runLocalEncryptedProfile decrypts a local profile file using the provided key and runs orchestrator
func (cmd *ActivateCmd) runLocalEncryptedProfile() error {
	if cmd.Key == "" {
		return fmt.Errorf("missing --key for encrypted profile file")
	}

	crypto := security.Crypto{EncryptionKey: cmd.Key}

	cfg, err := crypto.ReadAndDecryptFile(cmd.Profile)
	if err != nil {
		return fmt.Errorf("failed to decrypt profile: %w", err)
	}

	orch := orchestrator.NewProfileOrchestrator(cfg)
	if err := orch.ExecuteProfile(); err != nil {
		return err
	}

	log.Info("Profile fullflow completed successfully")

	return nil
}

// runLocalActivation executes local activation using the local service
func (cmd *ActivateCmd) runLocalActivation(ctx *commands.Context) error {
	// Create local activation command with current flags
	localCmd := LocalActivateCmd{
		AMTBaseCmd:          cmd.AMTBaseCmd, // Copy the base command with password
		LocalFlag:           cmd.Local,      // Set for backwards compatibility
		CCM:                 cmd.CCM,
		ACM:                 cmd.ACM,
		DNS:                 cmd.DNS,
		Hostname:            cmd.Hostname,
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
