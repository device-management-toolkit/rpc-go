/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package deactivate provides a public API for AMT deactivation.
//
// Each mode of the rpc deactivate command has its own function and options:
// Run deactivates AMT on this device directly, Remote lets an RPS server
// drive deactivation, and Console deactivates AMT on this device and then
// deletes the device from Console. Every function needs elevated privileges
// (admin/root) to access the HECI driver.
package deactivate

import (
	"errors"
	"net/url"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	log "github.com/sirupsen/logrus"
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

	// No server URL exists to resolve a relative endpoint against, so cleanup would be skipped.
	return run(cmd, ctx, func() error {
		if opts.AuthEndpoint != "" && !isAbsoluteHTTPURL(opts.AuthEndpoint) {
			return errRelativeAuthEndpoint
		}

		return nil
	})
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

// runner is the internal deactivate command, run through Kong's hooks.
type runner interface {
	Validate() error
	AfterApply(amt.Interface) error
	Run(*commands.Context) error
	GetWSManClient() interfaces.WSMANer
}

// run calls the hooks in Kong's order: the CLI root's Validate, which checks
// the ServerAuthFlags in ctx, then the command's Validate, AfterApply and Run.
// checks are the package's own option checks; they run after the root's
// Validate and before the command's, so every option is checked before any
// AMT access. run then closes the WSMAN client the command still holds,
// which the CLI leaves to process exit.
func run(cmd runner, ctx *commands.Context, checks ...func() error) error {
	if err := ctx.Validate(); err != nil {
		return err
	}

	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}

	if err := cmd.Validate(); err != nil {
		return err
	}

	amtCommand := amt.NewAMTCommand()

	if err := cmd.AfterApply(&amtCommand); err != nil {
		return err
	}

	ctx.AMTCommand = &amtCommand

	// Read the client after Run: it is created lazily inside Run.
	defer func() { closeWSMAN(cmd.GetWSManClient()) }()

	return cmd.Run(ctx)
}

// closeWSMAN releases a WSMAN client's connection. Over LME a held connection
// keeps the MEI device open, and the next call fails with "device busy".
func closeWSMAN(client interfaces.WSMANer) {
	if client == nil {
		return
	}

	// Only log a close failure so it never replaces Run's result.
	if err := client.Close(); err != nil {
		log.Debugf("closing WSMAN client: %v", err)
	}
}

func isAbsoluteHTTPURL(raw string) bool {
	parsed, err := url.Parse(raw)

	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}
