/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package deactivate provides a public API for local AMT deactivation.
package deactivate

import (
	"errors"
	"net/url"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
)

var errRelativeAuthEndpoint = errors.New("AuthEndpoint must be an absolute HTTP(S) URL")

// Options configures a local AMT deactivation operation.
type Options struct {
	// AMTPassword is the admin password for the AMT device.
	// Required for ACM mode; ignored for CCM mode.
	// If empty, the user will be prompted on stdin.
	AMTPassword string
	// PartialUnprovision performs a partial unprovision instead of full.
	// Only supported in ACM mode.
	PartialUnprovision bool
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool

	// The options below remove the device from Console after deactivation.
	// Cleanup runs when AuthEndpoint is set, or when AuthToken and DevicesEndpoint are set.

	// UUID overrides the device GUID read from AMT.
	UUID string
	// SkipCertCheck skips TLS certificate verification when connecting to Console.
	SkipCertCheck bool
	// TenantID is the Console tenant the device belongs to.
	TenantID string
	// AuthToken is a bearer token for Console.
	AuthToken string
	// AuthUsername and AuthPassword are exchanged at AuthEndpoint for a bearer token.
	AuthUsername string
	AuthPassword string
	// AuthEndpoint is the absolute Console token exchange URL.
	AuthEndpoint string
	// DevicesEndpoint is the absolute Console devices API URL.
	DevicesEndpoint string
}

// Run performs a local AMT deactivation.
// It initializes the AMT hardware interface, detects the control mode,
// sets up the WSMAN connection, and deactivates the device.
// Requires elevated privileges (admin/root) to access the HECI driver.
func Run(opts Options) error {
	cmd, ctx := newCommand(opts)

	// Validate is the embedded ServerAuthFlags', which Kong calls on the CLI root.
	if err := ctx.Validate(); err != nil {
		return err
	}

	// No server URL exists to resolve a relative endpoint against, so cleanup would be skipped.
	if opts.AuthEndpoint != "" && !isAbsoluteHTTPURL(opts.AuthEndpoint) {
		return errRelativeAuthEndpoint
	}

	if err := cmd.Validate(); err != nil {
		return err
	}

	amtCommand := amt.NewAMTCommand()

	if err := cmd.AfterApply(&amtCommand); err != nil {
		return err
	}

	ctx.AMTCommand = &amtCommand

	return cmd.Run(ctx)
}

// newCommand builds the local deactivate command and its context from opts.
func newCommand(opts Options) (*commands.DeactivateCmd, *commands.Context) {
	cmd := &commands.DeactivateCmd{
		Local:              true,
		PartialUnprovision: opts.PartialUnprovision,
		UUID:               opts.UUID,
	}

	ctx := &commands.Context{
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
		SkipCertCheck:    opts.SkipCertCheck,
		TenantID:         opts.TenantID,
		ServerAuthFlags: commands.ServerAuthFlags{
			AuthToken:       opts.AuthToken,
			AuthUsername:    opts.AuthUsername,
			AuthPassword:    opts.AuthPassword,
			AuthEndpoint:    opts.AuthEndpoint,
			DevicesEndpoint: opts.DevicesEndpoint,
		},
	}

	return cmd, ctx
}

func isAbsoluteHTTPURL(raw string) bool {
	parsed, err := url.Parse(raw)

	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}
