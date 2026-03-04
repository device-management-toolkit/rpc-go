/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/security"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/device"
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
	MEBxPassword        string `help:"MEBx password for AMT19+ TLS activation" env:"MEBX_PASSWORD" name:"mebxpassword"`
	SkipIPRenew         bool   `help:"Skip DHCP renewal of IP address if AMT becomes enabled" name:"skipIPRenew"`
	StopConfig          bool   `help:"Transition AMT from in-provisioning to pre-provisioning state" name:"stopConfig"`
}

// RequiresAMTPassword indicates whether this command requires AMT password
// For activate, password is required for local activation (to set the AMT password).
// The stopConfig path does not require an AMT password.
func (cmd *ActivateCmd) RequiresAMTPassword() bool {
	return !cmd.StopConfig
}

// Validate checks the command configuration and determines activation mode
func (cmd *ActivateCmd) Validate() error {
	log.Trace("Entering Validate method of ActivateCmd")

	// Determine if caller intends local activation (explicit --local or local-only flags)
	localIntent := cmd.Local || cmd.hasLocalActivationFlags()

	// Resolve local-vs-remote precedence when both are present.
	// - For HTTP(S) URL: keep the URL (used to fetch a profile and orchestrate steps) and ignore local flags.
	// - For WS/WSS URL: mixing with --local is invalid and should fail early to preserve legacy semantics.
	if localIntent && cmd.URL != "" {
		lowerURL := strings.ToLower(cmd.URL)
		if strings.HasPrefix(lowerURL, "http://") || strings.HasPrefix(lowerURL, "https://") {
			log.Warn("Both --url and local activation flags detected; proceeding with local activation via http://")
			// Clear URL so we don't trigger HTTP profile fullflow during local runs (prevents recursion)
			cmd.URL = ""
		}
	}

	// If URL is specified, split behavior by scheme
	if cmd.URL != "" {
		if strings.HasPrefix(strings.ToLower(cmd.URL), "ws://") || strings.HasPrefix(strings.ToLower(cmd.URL), "wss://") {
			// --local must not be combined with ws/wss remote URLs
			if cmd.Local {
				return fmt.Errorf("cannot specify both --local and --url flags")
			}
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

			if cmd.ProvisioningCert != "" {
				return fmt.Errorf("--provisioningCert flag is only valid for local activation, not with --url")
			}

			if cmd.ProvisioningCertPwd != "" {
				return fmt.Errorf("--provisioningCertPwd flag is only valid for local activation, not with --url")
			}

			if cmd.SkipIPRenew {
				return fmt.Errorf("--skipIPRenew flag is only valid for local activation, not with --url")
			}

			// if cmd.AuthToken != "" || cmd.AuthUsername != "" || cmd.AuthPassword != "" || cmd.Key != "" {
			// 	return fmt.Errorf("HTTP auth/decryption flags are not valid with ws/wss --url")
			// }

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

	// If --profile is provided, handle file vs. name
	if cmd.Profile != "" {
		// In local intent, ignore a non-file profile name to avoid forcing ws/wss URL
		if localIntent && !looksLikeFilePath(cmd.Profile) {
			log.Warn("Ignoring --profile as a name for local activation; provide a file path to run a local profile fullflow")

			cmd.Profile = ""
		}

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

		// Otherwise treat as legacy profile name; require ws/wss URL (only when not in local intent)
		if !localIntent && cmd.URL == "" {
			return fmt.Errorf("--profile as a name requires --url with ws/wss scheme")
		}
	}

	// If --local is specified or local flags are present, it's local mode
	if localIntent {
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
		cmd.ProvisioningCert != "" || cmd.ProvisioningCertPwd != "" || cmd.SkipIPRenew
}

// Run executes the activate command based on detected mode
func (cmd *ActivateCmd) Run(ctx *commands.Context) error {
	log.Tracef("Entering Run method of ActivateCmd. Context: %s", ctx.AuthEndpoint)

	// Local activation paths require AMT password unless stopConfig.
	if (cmd.Local || cmd.hasLocalActivationFlags()) && cmd.RequiresAMTPassword() {
		if err := cmd.EnsureAMTPassword(ctx, cmd); err != nil {
			return err
		}

		if err := cmd.EnsureWSMAN(ctx); err != nil {
			return err
		}
	}
	// Determine activation mode based on flags
	if cmd.URL != "" {
		// Remote URL provided: choose path by scheme
		lower := strings.ToLower(cmd.URL)
		if strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
			// Legacy remote activation path. If device already activated (control mode != 0),
			// a password is required downstream for authenticated operations; prompt now if missing.
			if cmd.ControlMode != 0 && strings.TrimSpace(ctx.AMTPassword) == "" {
				if err := cmd.EnsureAMTPassword(ctx, cmd); err != nil {
					return err
				}
				// WSMAN not required for remote activation, so we do not call EnsureWSMAN here.
			}

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

		return cmd.runLocalProfileFullflow(ctx)
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
		ServerAuthFlags: ctx.ServerAuthFlags,
	}

	// Validate and execute the remote command
	if err := remoteCmd.Validate(); err != nil {
		return err
	}

	return remoteCmd.Run(ctx)
}

// runHttpProfileFullflow fetches a profile over HTTP(S) and runs the orchestrator.
// Order: authenticate → fetch profile → resolve passwords → add device (with passwords) → execute.
func (cmd *ActivateCmd) runHttpProfileFullflow(ctx *commands.Context) error {
	// Build the fetcher with all credentials — it handles authentication internally
	fetcher := &profile.ProfileFetcher{
		URL:           cmd.URL,
		Token:         ctx.AuthToken,
		Username:      ctx.AuthUsername,
		Password:      ctx.AuthPassword,
		AuthEndpoint:  ctx.AuthEndpoint,
		SkipCertCheck: ctx.SkipCertCheck,
	}

	// Allow client-provided key for HTTP bodies or envelopes missing key
	if cmd.Key != "" {
		fetcher.ClientKey = cmd.Key
	}

	// Authenticate once using the fetcher's own auth logic, then reuse the token
	token, err := fetcher.GetToken()
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Set the token on the fetcher so FetchProfile() skips re-authentication
	fetcher.Token = token

	cfg, err := fetcher.FetchProfile()
	if err != nil {
		return fmt.Errorf("failed to fetch profile: %w", err)
	}

	// Resolve AMT/MEBx/MPS passwords — generate random ones when the profile requests it.
	// This happens before device registration so the console already has the correct passwords.
	amtPassword, mebxPassword, mpsPassword, err := profile.ResolvePasswords(&cfg)
	if err != nil {
		return fmt.Errorf("failed to resolve passwords: %w", err)
	}

	// Resolve console base URL and device GUID for device registration and potential cleanup.
	consoleBaseURL, guid, err := cmd.resolveConsoleInfo(ctx, fetcher)
	if err != nil {
		return fmt.Errorf("failed to resolve console info: %w", err)
	}

	// Add device to console with resolved passwords
	if err := cmd.addDeviceToConsole(ctx, consoleBaseURL, token, guid, amtPassword, mebxPassword, mpsPassword); err != nil {
		log.Warnf("Failed to add device to console: %v", err)

		if !cmd.promptUserToProceed(err) {
			return fmt.Errorf("activation aborted: %w", err)
		}

		log.Info("Proceeding with activation despite add-device failure")
	}

	// Pass through the current AMT password (if provided) so orchestrator can
	// rotate to the profile's AdminPassword without prompting.
	orch := orchestrator.NewProfileOrchestrator(cfg, ctx.AMTPassword, cmd.MEBxPassword, ctx.SkipAMTCertCheck)
	if err := orch.ExecuteProfile(); err != nil {
		// When CIRA configuration fails, clear the MPS password from the console
		// to avoid confusing users with a stale password in the device record.
		if strings.Contains(err.Error(), "CIRA") && mpsPassword != "" {
			cmd.clearMPSPasswordFromConsole(consoleBaseURL, token, guid, ctx.SkipCertCheck)
		}

		return err
	}

	log.Info("Profile fullflow completed successfully")

	return nil
}

// resolveConsoleInfo extracts the console base URL from the fetcher and determines the device GUID.
func (cmd *ActivateCmd) resolveConsoleInfo(ctx *commands.Context, fetcher *profile.ProfileFetcher) (string, string, error) {
	parsed, err := url.Parse(fetcher.URL)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %w", err)
	}

	consoleBaseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	guid := cmd.UUID
	if guid == "" && ctx.AMTCommand != nil {
		guid, err = ctx.AMTCommand.GetUUID()
		if err != nil {
			return "", "", fmt.Errorf("failed to get device UUID: %w", err)
		}
	}

	return consoleBaseURL, guid, nil
}

// clearMPSPasswordFromConsole removes the MPS password from the device record in the console.
// This is called when CIRA configuration fails so users are not confused by a stale password.
func (cmd *ActivateCmd) clearMPSPasswordFromConsole(consoleBaseURL, token, guid string, skipCertCheck bool) {
	if guid == "" {
		log.Warn("Cannot clear MPS password: device GUID is unknown")

		return
	}

	if err := device.ClearDeviceMPSPassword(consoleBaseURL, token, guid, skipCertCheck); err != nil {
		log.Warnf("Failed to clear MPS password from console after CIRA failure: %v", err)
	} else {
		log.Info("MPS password cleared from console after CIRA configuration failure")
	}
}

// addDeviceToConsole registers or updates the device in the console database before activation.
// It tries POST first; if the device already exists, it falls back to PATCH.
func (cmd *ActivateCmd) addDeviceToConsole(ctx *commands.Context, consoleBaseURL, token, guid, amtPassword, mebxPassword, mpsPassword string) error {
	hostname := cmd.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	payload := device.DevicePayload{
		GUID:         guid,
		Hostname:     hostname,
		FriendlyName: cmd.FriendlyName,
		Tags:         []string{},
		MPSUsername:  "admin",
		Username:     "admin",
		Password:     amtPassword,
		MEBXPassword: mebxPassword,
		MPSPassword:  mpsPassword,
	}

	err := device.AddDevice(consoleBaseURL, token, payload, ctx.SkipCertCheck)
	if err == nil {
		return nil
	}

	// If POST failed (device likely already exists), try PATCH to update.
	log.Debugf("POST failed (%v), attempting PATCH to update existing device", err)

	if updateErr := device.UpdateDevice(consoleBaseURL, token, payload, ctx.SkipCertCheck); updateErr != nil {
		return fmt.Errorf("add failed: %w; update also failed: %v", err, updateErr)
	}

	return nil
}

// promptUserToProceed asks the user whether to continue with activation after a failure.
func (cmd *ActivateCmd) promptUserToProceed(err error) bool {
	fmt.Printf("Failed to add device to console: %v\n", err)
	fmt.Print("Do you want to proceed with activation? (y/n): ")

	reader := bufio.NewReader(os.Stdin)

	answer, readErr := reader.ReadString('\n')
	if readErr != nil {
		return false
	}

	answer = strings.TrimSpace(strings.ToLower(answer))

	return answer == "y" || answer == "yes"
}

// runLocalProfileFullflow loads a local profile file (optionally decrypt) and runs the orchestrator
func (cmd *ActivateCmd) runLocalProfileFullflow(ctx *commands.Context) error {
	// Prefer existing loader for plaintext YAML
	if cmd.Key == "" {
		c, err := profile.LoadProfile(cmd.Profile)
		if err != nil {
			return fmt.Errorf("failed to load profile: %w", err)
		}

		orch := orchestrator.NewProfileOrchestrator(c, ctx.AMTPassword, cmd.MEBxPassword, ctx.SkipAMTCertCheck)
		if err := orch.ExecuteProfile(); err != nil {
			return err
		}

		log.Info("Profile fullflow completed successfully")

		return nil
	}

	// Encrypted file path handling using go-wsman security helper
	return cmd.runLocalEncryptedProfile(ctx)
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
func (cmd *ActivateCmd) runLocalEncryptedProfile(ctx *commands.Context) error {
	if cmd.Key == "" {
		return fmt.Errorf("missing --key for encrypted profile file")
	}

	crypto := security.Crypto{EncryptionKey: cmd.Key}

	cfg, err := crypto.ReadAndDecryptFile(cmd.Profile)
	if err != nil {
		return fmt.Errorf("failed to decrypt profile: %w", err)
	}

	orch := orchestrator.NewProfileOrchestrator(cfg, ctx.AMTPassword, cmd.MEBxPassword, ctx.SkipAMTCertCheck)
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
		MEBxPassword:        cmd.MEBxPassword,
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
