/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/security"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
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

	// consoleURL is preserved from URL when --local clears it, for console device registration.
	consoleURL string
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
			// Preserve URL for console device registration, then clear to prevent HTTP profile fullflow
			cmd.consoleURL = cmd.URL
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

// runHttpProfileFullflow fetches a profile over HTTP(S) and runs the orchestrator
func (cmd *ActivateCmd) runHttpProfileFullflow(ctx *commands.Context) error {
	// Reuse ProfileFetcher
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

	if token != "" {
		fetcher.Token = token
	}

	cfg, err := fetcher.FetchProfile()
	if err != nil {
		return fmt.Errorf("failed to fetch profile: %w", err)
	}

	// Resolve AMT/MEBx/MPS passwords — generate random ones when the profile requests it.
	amtPassword, mebxPassword, mpsPassword, err := profile.ResolvePasswords(&cfg)
	if err != nil {
		return fmt.Errorf("failed to resolve passwords: %w", err)
	}

	// Resolve console base URL and device GUID for device registration and potential cleanup.
	consoleBaseURL, guid, err := cmd.resolveConsoleInfo(ctx, fetcher.URL)
	if err != nil {
		return fmt.Errorf("failed to resolve console info: %w", err)
	}

	// Add device to console with resolved passwords
	hasCIRA := cfg.Configuration.AMTSpecific.CIRA.MPSAddress != ""

	addDeviceFailed := cmd.addDeviceToConsole(ctx, consoleBaseURL, token, guid, amtPassword, mebxPassword, mpsPassword, hasCIRA, &cfg)
	if addDeviceFailed != nil {
		return fmt.Errorf("failed to add device to console: %w", addDeviceFailed)
	}

	// Pass through the current AMT password (if provided) so orchestrator can
	// rotate to the profile's AdminPassword without prompting.
	orch := orchestrator.NewProfileOrchestrator(cfg, ctx.AMTPassword, cmd.MEBxPassword, ctx.SkipAMTCertCheck)
	if err := orch.ExecuteProfile(); err != nil {
		// When CIRA configuration fails, clear the MPS password from the console
		if errors.Is(err, orchestrator.ErrCIRAConfiguration) && mpsPassword != "" {
			cmd.clearMPSPasswordFromConsole(consoleBaseURL, token, guid, ctx.SkipCertCheck)
		}

		return err
	}

	log.Info("Profile fullflow completed successfully")

	return nil
}

// extracts the console base URL from the given URL and determines the device GUID.
func (cmd *ActivateCmd) resolveConsoleInfo(ctx *commands.Context, rawURL string) (string, string, error) {
	parsed, err := url.Parse(rawURL)
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

// removes the MPS password from the device record in the console.
func (cmd *ActivateCmd) clearMPSPasswordFromConsole(consoleBaseURL, token, guid string, skipCertCheck bool) {
	if guid == "" {
		log.Warn("Cannot clear MPS password: device GUID is unknown")

		return
	}

	if err := device.ClearDeviceMPSPassword(consoleBaseURL, token, guid, skipCertCheck); err != nil {
		log.Warnf("failed to clear MPS password: %v", err)
	} else {
		log.Info("MPS password cleared after CIRA failure")
	}
}

// addDeviceToConsole registers or updates the device in the console before activation.
func (cmd *ActivateCmd) addDeviceToConsole(ctx *commands.Context, consoleBaseURL, token, guid, amtPassword, mebxPassword, mpsPassword string, hasCIRA bool, cfg *config.Configuration) error {
	hostname := cmd.Hostname
	if hostname == "" {
		if hasCIRA {
			hostname, _ = os.Hostname()
		} else {
			hostname = getLocalIP()
		}
	}

	friendlyName := cmd.FriendlyName
	if friendlyName == "" {
		friendlyName, _ = os.Hostname()
		if friendlyName == "" {
			friendlyName = hostname
		}
	}

	useTLS, allowSelfSigned := cmd.resolveTLSFlags(cfg)

	payload := device.DevicePayload{
		GUID:            guid,
		Hostname:        hostname,
		FriendlyName:    friendlyName,
		Tags:            cfg.Tags,
		Username:        "admin",
		Password:        amtPassword,
		MEBXPassword:    mebxPassword,
		UseTLS:          useTLS,
		AllowSelfSigned: allowSelfSigned,
	}

	if hasCIRA {
		payload.MPSUsername = "admin"
		payload.MPSPassword = mpsPassword
	} else {
		payload.MPSUsername = ""
		payload.MPSPassword = ""
	}

	err := device.AddDevice(consoleBaseURL, token, payload, ctx.SkipCertCheck)
	if err == nil {
		return nil
	}

	// Only fall back to PATCH when the device already exists (HTTP 409 Conflict).
	var statusErr *device.StatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusConflict {
		log.Debugf("Device already exists in console, updating device credentials")

		if updateErr := device.UpdateDevice(consoleBaseURL, token, payload, ctx.SkipCertCheck); updateErr != nil {
			return fmt.Errorf("update also failed: %v", updateErr)
		}

		return nil
	}

	return err
}

// resolveTLSFlags determines UseTLS and AllowSelfSigned for the device payload.
// 1. If the profile has TLS enabled → both true.
// 2. If the device enforces TLS on local ports (AMT 19+) → both true.
// 3. Otherwise query the device's current Remote TLS settings via WSMAN:
//   - Remote TLS enabled with AcceptNonSecureConnections=false → both true.
//   - All other cases → both false.
func (cmd *ActivateCmd) resolveTLSFlags(cfg *config.Configuration) (useTLS, allowSelfSigned bool) {
	if cfg.Configuration.TLS.Enabled {
		return true, true
	}

	if cmd.LocalTLSEnforced {
		return true, true
	}

	if cmd.WSMan == nil {
		log.Debug("WSMAN not available, skipping TLS settings check")

		return false, false
	}

	enumerateRsp, err := cmd.WSMan.EnumerateTLSSettingData()
	if err != nil {
		log.Warnf("Failed to enumerate TLS settings: %v", err)

		return false, false
	}

	pullRsp, err := cmd.WSMan.PullTLSSettingData(enumerateRsp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		log.Warnf("Failed to pull TLS settings: %v", err)

		return false, false
	}

	for _, item := range pullRsp.Body.PullResponse.SettingDataItems {
		if item.InstanceID == configure.RemoteTLSInstanceId && item.Enabled && !item.AcceptNonSecureConnections {
			return true, true
		}
	}

	return false, false
}

// getLocalIP returns the first non-loopback IPv4 address, falling back to os.Hostname().
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}

			if ip4 := ipNet.IP.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}

	h, err := os.Hostname()
	if err == nil && h != "" {
		return h
	}

	return "unknown"
}

// runLocalProfileFullflow loads a local profile file (optionally decrypt) and runs the orchestrator
func (cmd *ActivateCmd) runLocalProfileFullflow(ctx *commands.Context) error {
	var cfg config.Configuration

	var err error

	if cmd.Key == "" {
		cfg, err = profile.LoadProfile(cmd.Profile)
		if err != nil {
			return fmt.Errorf("failed to load profile: %w", err)
		}
	} else {
		crypto := security.Crypto{EncryptionKey: cmd.Key}

		cfg, err = crypto.ReadAndDecryptFile(cmd.Profile)
		if err != nil {
			return fmt.Errorf("failed to decrypt profile: %w", err)
		}
	}

	return cmd.orchestrateWithConsole(ctx, cfg)
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

// orchestrateWithConsole resolves passwords, optionally registers the device with
// the console, and runs the profile orchestrator. Used by local profile flows.
func (cmd *ActivateCmd) orchestrateWithConsole(ctx *commands.Context, cfg config.Configuration) error {
	// Resolve AMT/MEBx/MPS passwords — generate random ones when the profile requests it.
	amtPassword, mebxPassword, mpsPassword, err := profile.ResolvePasswords(&cfg)
	if err != nil {
		return fmt.Errorf("failed to resolve passwords: %w", err)
	}

	var consoleBaseURL, guid, token string

	// Determine console URL: from preserved --url, or from an absolute --auth-endpoint.
	effectiveConsoleURL := cmd.consoleURL
	if effectiveConsoleURL == "" && isAbsoluteURL(ctx.AuthEndpoint) {
		effectiveConsoleURL = ctx.AuthEndpoint
	}

	// Error if auth credentials are provided but no console URL could be resolved.
	hasAuth := ctx.AuthToken != "" || ctx.AuthUsername != "" || ctx.AuthPassword != ""
	if hasAuth && effectiveConsoleURL == "" {
		if ctx.AuthEndpoint != "" && !isAbsoluteURL(ctx.AuthEndpoint) {
			return fmt.Errorf("--auth-endpoint %q is not an absolute URL; provide a full URL (e.g., https://host/api/v1/authorize) or use --url to specify the console address", ctx.AuthEndpoint)
		}

		return fmt.Errorf("auth credentials provided but no console URL available; use --url or provide an absolute --auth-endpoint (e.g., https://host/api/v1/authorize)")
	}

	// Register device with console if a console URL is available and auth is provided.
	if effectiveConsoleURL != "" {
		token, err = cmd.authenticateForConsole(ctx, effectiveConsoleURL)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		if token != "" {
			consoleBaseURL, guid, err = cmd.resolveConsoleInfo(ctx, effectiveConsoleURL)
			if err != nil {
				return fmt.Errorf("failed to resolve console info: %w", err)
			}

			hasCIRA := cfg.Configuration.AMTSpecific.CIRA.MPSAddress != ""

			if addErr := cmd.addDeviceToConsole(ctx, consoleBaseURL, token, guid, amtPassword, mebxPassword, mpsPassword, hasCIRA, &cfg); addErr != nil {
				return fmt.Errorf("failed to add device to console: %w", addErr)
			}
		}
	}

	orch := orchestrator.NewProfileOrchestrator(cfg, ctx.AMTPassword, cmd.MEBxPassword, ctx.SkipAMTCertCheck)
	if err := orch.ExecuteProfile(); err != nil {
		if consoleBaseURL != "" && token != "" && errors.Is(err, orchestrator.ErrCIRAConfiguration) && mpsPassword != "" {
			cmd.clearMPSPasswordFromConsole(consoleBaseURL, token, guid, ctx.SkipCertCheck)
		}

		return err
	}

	log.Info("Profile fullflow completed successfully")

	return nil
}

// isAbsoluteURL reports whether s starts with http:// or https://.
func isAbsoluteURL(s string) bool {
	lower := strings.ToLower(s)

	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// authenticateForConsole obtains a bearer token for console API calls.
// Returns ("", nil) when no credentials are available (skips registration silently).
func (cmd *ActivateCmd) authenticateForConsole(ctx *commands.Context, consoleURL string) (string, error) {
	if ctx.AuthToken != "" {
		return ctx.AuthToken, nil
	}

	if ctx.AuthUsername == "" || ctx.AuthPassword == "" {
		return "", nil
	}

	parsed, err := url.Parse(consoleURL)
	if err != nil {
		return "", fmt.Errorf("invalid console URL: %w", err)
	}

	baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	return profile.Authenticate(baseURL, ctx.AuthUsername, ctx.AuthPassword, ctx.AuthEndpoint, ctx.SkipCertCheck, 0)
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
