/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/device"
	"github.com/device-management-toolkit/rpc-go/v2/internal/profile"
	"github.com/device-management-toolkit/rpc-go/v2/internal/rps"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// Control mode constants for better readability
const (
	ControlModeCCM = 1
	ControlModeACM = 2
)

// setupTLSConfig creates TLS configuration if local TLS is enforced
func (cmd *DeactivateCmd) setupTLSConfig(ctx *Context) *tls.Config {
	tlsConfig := &tls.Config{}

	if cmd.LocalTLSEnforced {
		controlMode := cmd.GetControlMode()
		tlsConfig = certs.GetTLSConfig(&controlMode, nil, ctx.SkipAMTCertCheck)
	}

	return tlsConfig
}

// DeactivateCmd represents the deactivate command
type DeactivateCmd struct {
	AMTBaseCmd
	Local              bool   `help:"Execute command to AMT directly without cloud interaction" short:"l"`
	PartialUnprovision bool   `help:"Partially unprovision the device. Only supported with -local flag" name:"partial"`
	URL                string `help:"Server URL for remote deactivation" short:"u"`
	Force              bool   `help:"Force deactivation even if device is not matched in MPS" short:"f"`
	UUID               string `help:"UUID override" name:"uuid"`

	// consoleURL is preserved from URL when --local clears it, for console device deletion.
	consoleURL string
}

// RequiresAMTPassword indicates whether this command requires AMT password
// For deactivate, password is required for both local and remote modes
func (cmd *DeactivateCmd) RequiresAMTPassword() bool {
	// Password required for local mode or remote mode (when URL is provided)
	return cmd.Local || cmd.URL != ""
}

// Validate implements Kong's extensible validation interface for business logic validation
func (cmd *DeactivateCmd) Validate() error {
	// When --local and HTTP(S) --url are both present, preserve the URL for
	// console device deletion and clear cmd.URL so Run takes the local path.
	if cmd.Local && cmd.URL != "" {
		lower := strings.ToLower(cmd.URL)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			if cmd.PartialUnprovision {
				return fmt.Errorf("partial unprovisioning is not supported with HTTP(S) --url")
			}

			log.Warn("Both --url and --local detected; proceeding with local deactivation and console device deletion")

			cmd.consoleURL = cmd.URL
			cmd.URL = ""
		}
	}

	// HTTP(S) URL without --local: full HTTP console flow
	if cmd.URL != "" {
		lower := strings.ToLower(cmd.URL)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			if cmd.PartialUnprovision {
				return fmt.Errorf("partial unprovisioning is not supported with HTTP(S) --url")
			}

			return nil
		}
	}

	// Ensure either local mode or URL is provided, but not both
	if cmd.Local && cmd.URL != "" {
		return fmt.Errorf("provide either a 'url' or a 'local', but not both")
	}

	// Ensure at least one mode is selected
	if !cmd.Local && cmd.URL == "" {
		return fmt.Errorf("-u flag is required when not using local mode")
	}

	// Business logic validation: partial unprovision only works with local mode
	if cmd.PartialUnprovision && !cmd.Local {
		return fmt.Errorf("partial unprovisioning is only supported with local flag")
	}

	return nil
}

// Run executes the deactivate command
func (cmd *DeactivateCmd) Run(ctx *Context) error {
	if cmd.URL != "" {
		lower := strings.ToLower(cmd.URL)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			return cmd.executeHttpConsoleDeactivate(ctx)
		}
	}

	// Resolve AMT password (only when required)
	if cmd.RequiresAMTPassword() {
		if err := cmd.EnsureAMTPassword(ctx, cmd); err != nil {
			return err
		}

		if cmd.Local { // local path needs WSMAN
			if err := cmd.EnsureWSMAN(ctx); err != nil {
				return err
			}
		}
	}

	if cmd.Local {
		// Pre-resolve device GUID before deactivation — AMT cannot respond after unprovision.
		preGUID, _ := cmd.resolveGUID(ctx)

		// For local deactivation
		if err := cmd.executeLocalDeactivate(ctx); err != nil {
			return err
		}
		// If auth credentials are provided, also delete device from console DB
		return cmd.deleteDeviceFromConsoleIfAuth(ctx, preGUID)
	}

	// For remote deactivation via RPS
	return cmd.executeRemoteDeactivate(ctx)
}

// executeRemoteDeactivate handles remote deactivation via RPS
func (cmd *DeactivateCmd) executeRemoteDeactivate(ctx *Context) error {
	// Create RPS request
	req := &rps.Request{
		Command:          utils.CommandDeactivate,
		URL:              cmd.URL,
		Password:         ctx.AMTPassword,
		LogLevel:         ctx.LogLevel,
		JsonOutput:       ctx.JsonOutput,
		Verbose:          ctx.Verbose,
		SkipCertCheck:    ctx.SkipCertCheck,
		SkipAmtCertCheck: ctx.SkipAMTCertCheck,
		Force:            cmd.Force,
		TenantID:         ctx.TenantID,
	}

	// Execute via RPS
	return rps.ExecuteCommand(req)
}

// authenticate, then deactivate locally and delete device from db.
func (cmd *DeactivateCmd) executeHttpConsoleDeactivate(ctx *Context) error {
	parsed, err := url.Parse(cmd.URL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	consoleBaseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	// Authenticate with the console
	token, err := cmd.authenticateWithConsole(ctx, consoleBaseURL)
	if err != nil {
		return fmt.Errorf("console authentication failed: %w", err)
	}

	// Resolve device GUID
	guid, err := cmd.resolveGUID(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve device GUID: %w", err)
	}

	// Ensure AMT password for local deactivation
	if err := cmd.EnsureAMTPassword(ctx, cmd); err != nil {
		return err
	}

	if err := cmd.EnsureWSMAN(ctx); err != nil {
		return err
	}

	// Perform local deactivation
	if err := cmd.executeLocalDeactivate(ctx); err != nil {
		return err
	}

	// Best-effort console cleanup — device is already deactivated at this point.
	if err := device.DeleteDevice(consoleBaseURL, token, guid, ctx.SkipCertCheck); err != nil {
		return fmt.Errorf("device deactivated but failed to delete from console: %w", err)
	}

	return nil
}

// authenticateWithConsole obtains a bearer token from the console using the provided credentials.
func (cmd *DeactivateCmd) authenticateWithConsole(ctx *Context, consoleBaseURL string) (string, error) {
	// Direct token provided — use it
	if ctx.AuthToken != "" {
		return ctx.AuthToken, nil
	}

	// Username/password — exchange for a token
	if ctx.AuthUsername != "" && ctx.AuthPassword != "" {
		return profile.Authenticate(consoleBaseURL, ctx.AuthUsername, ctx.AuthPassword, ctx.AuthEndpoint, ctx.SkipCertCheck, 0)
	}

	return "", fmt.Errorf("authentication required: provide --auth-token or --auth-username and --auth-password")
}

// resolveGUID determines the device GUID from the command flags or the AMT hardware.
func (cmd *DeactivateCmd) resolveGUID(ctx *Context) (string, error) {
	if cmd.UUID != "" {
		return cmd.UUID, nil
	}

	if ctx.AMTCommand != nil {
		guid, err := ctx.AMTCommand.GetUUID()
		if err != nil {
			return "", fmt.Errorf("failed to get device UUID: %w", err)
		}

		return guid, nil
	}

	return "", fmt.Errorf("unable to determine device GUID; provide --uuid")
}

// deleteDeviceFromConsoleIfAuth deletes the device from the console DB after local deactivation
// when auth credentials (--auth-username/--auth-password or --auth-token with --auth-endpoint) are provided.
// preResolvedGUID must be obtained before deactivation since AMT cannot respond after unprovision.
// If no auth credentials are present, this is a no-op.
func (cmd *DeactivateCmd) deleteDeviceFromConsoleIfAuth(ctx *Context, preResolvedGUID string) error {
	// Partial unprovision leaves the device partially active — do not delete from console.
	if cmd.PartialUnprovision {
		return nil
	}

	effectiveConsoleURL := cmd.consoleURL
	if effectiveConsoleURL == "" && isAbsoluteURL(ctx.AuthEndpoint) {
		effectiveConsoleURL = ctx.AuthEndpoint
	}

	hasAuth := ctx.AuthToken != "" || ctx.AuthUsername != "" || ctx.AuthPassword != ""
	if !hasAuth {
		return nil // no auth credentials, skip console deletion
	}

	if effectiveConsoleURL == "" {
		if ctx.AuthEndpoint != "" && !isAbsoluteURL(ctx.AuthEndpoint) {
			return fmt.Errorf("device deactivated but --auth-endpoint %q is not an absolute URL; provide a full URL (e.g., http://host/api/v1/authorize)", ctx.AuthEndpoint)
		}

		return fmt.Errorf("device deactivated but no console URL available; provide an absolute --auth-endpoint (e.g., http://host/api/v1/authorize)")
	}

	parsed, err := url.Parse(effectiveConsoleURL)
	if err != nil {
		return fmt.Errorf("device deactivated but invalid console URL: %w", err)
	}

	consoleBaseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	token, err := cmd.authenticateWithConsole(ctx, consoleBaseURL)
	if err != nil {
		return fmt.Errorf("device deactivated but console authentication failed: %w", err)
	}

	if preResolvedGUID == "" {
		return fmt.Errorf("device deactivated but unable to determine device GUID; provide --uuid")
	}

	if err := device.DeleteDevice(consoleBaseURL, token, preResolvedGUID, ctx.SkipCertCheck); err != nil {
		return fmt.Errorf("device deactivated but failed to delete from console: %w", err)
	}

	log.Info("Device deleted from console")

	return nil
}

// isAbsoluteURL reports whether s starts with http:// or https://.
func isAbsoluteURL(s string) bool {
	lower := strings.ToLower(s)

	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// executeLocalDeactivate handles local deactivation
func (cmd *DeactivateCmd) executeLocalDeactivate(ctx *Context) error {
	// Use the control mode already retrieved in AMTBaseCmd.AfterApply()
	controlMode := cmd.GetControlMode()

	// Deactivate based on the control mode
	switch controlMode {
	case ControlModeCCM:
		if cmd.PartialUnprovision {
			return fmt.Errorf("partial unprovisioning is only supported in ACM mode")
		}

		return cmd.deactivateCCM(ctx)
	case ControlModeACM:
		return cmd.deactivateACM()
	default:
		log.Error("Deactivation failed. Device control mode: " + utils.InterpretControlMode(controlMode))

		return utils.UnableToDeactivate
	}
}

// deactivateACM handles ACM mode deactivation
func (cmd *DeactivateCmd) deactivateACM() error {
	// Execute deactivation operation
	if cmd.PartialUnprovision {
		return cmd.executePartialUnprovision()
	}

	return cmd.executeFullUnprovision()
}

// executePartialUnprovision performs partial unprovision operation
func (cmd *DeactivateCmd) executePartialUnprovision() error {
	_, err := cmd.WSMan.PartialUnprovision()
	if err != nil {
		log.Error("Status: Unable to partially deactivate ", err)

		return utils.UnableToDeactivate
	}

	log.Info("Status: Device partially deactivated")

	return nil
}

// executeFullUnprovision performs full unprovision operation
func (cmd *DeactivateCmd) executeFullUnprovision() error {
	_, err := cmd.WSMan.Unprovision(1)
	if err != nil {
		log.Error("Status: Unable to deactivate ", err)

		return utils.UnableToDeactivate
	}

	log.Info("Status: Device deactivated")

	return nil
}

// deactivateCCM handles CCM mode deactivation
func (cmd *DeactivateCmd) deactivateCCM(ctx *Context) error {
	if ctx.AMTPassword != "" {
		log.Warn("AMT password not required for CCM deactivation")
	}

	status, err := ctx.AMTCommand.Unprovision()
	if err != nil || status != 0 {
		log.Error("Status: Failed to deactivate ", err)

		return utils.DeactivationFailed
	}

	log.Info("Status: Device deactivated")

	return nil
}
