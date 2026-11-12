/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package deactivate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
)

var (
	errMissingConsoleURL = errors.New("Console URL is required")
	errRelativeURL       = errors.New("URL must be an absolute HTTP(S) URL")
	// The command reports this only after reading AMT.
	errMissingConsoleAuth = errors.New("authentication required: provide --auth-token or --auth-username and --auth-password")
)

// ConsoleOptions configures an AMT deactivation that then deletes the device
// from Console. AuthToken, or AuthUsername and AuthPassword, must be set.
type ConsoleOptions struct {
	// URL is the Console URL, with the http or https scheme and a host
	// (required). Only its scheme and host are used.
	URL string
	// AMTPassword is the device's AMT admin password. If empty, the user will
	// be prompted on stdin.
	AMTPassword string
	// UUID overrides the device GUID read from AMT, which names the device
	// to delete from Console.
	UUID string
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool
	// SkipCertCheck skips TLS certificate verification when connecting to Console.
	SkipCertCheck bool
	// TenantID is the Console tenant the device belongs to.
	TenantID string
	// AuthToken is a bearer token for Console.
	AuthToken string
	// AuthUsername and AuthPassword are exchanged for a bearer token when
	// AuthToken is empty.
	AuthUsername string
	AuthPassword string
	// AuthEndpoint is the Console token exchange URL. It may be a path on the
	// URL's host; if empty, /api/v1/authorize and then
	// /mps/login/api/v1/authorize are tried.
	AuthEndpoint string
	// DevicesEndpoint is the absolute Console devices API URL. If empty,
	// /api/v1/devices on the Console host is used.
	DevicesEndpoint string
}

// Console authenticates with Console, deactivates AMT on this device, and
// deletes the device from Console, like "rpc deactivate --url https://…".
// It returns an error if the device was deactivated but could not be deleted
// from Console. If the device GUID cannot be read from AMT and opts.UUID is
// empty, the Console deletion is skipped and Console still returns nil once
// AMT is deactivated. If opts.AMTPassword is empty, the user will be prompted
// on stdin. Requires elevated privileges (admin/root) to access the HECI driver.
func Console(opts ConsoleOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}

	cmd, ctx := newConsoleCommand(opts)

	return run(cmd, ctx, opts.validateAuth)
}

// validate rejects a URL the command would run in another mode, or could
// not delete the device from.
func (opts ConsoleOptions) validate() error {
	if opts.URL == "" {
		return errMissingConsoleURL
	}

	// The command lets RPS drive deactivation for a ws(s) URL.
	if isWebSocketURL(opts.URL) {
		return fmt.Errorf("unsupported url scheme: %s; use Remote for a ws(s) URL", opts.URL)
	}

	if !isHTTPURL(opts.URL) {
		return fmt.Errorf("unsupported url scheme: %s", opts.URL)
	}

	// The command would deactivate the device and only then fail to reach Console.
	if !isAbsoluteHTTPURL(opts.URL) {
		return errRelativeURL
	}

	return nil
}

// validateAuth rejects options without Console credentials, which the
// command reports only after reading AMT.
func (opts ConsoleOptions) validateAuth() error {
	if strings.TrimSpace(opts.AuthToken) != "" || (opts.AuthUsername != "" && opts.AuthPassword != "") {
		return nil
	}

	return errMissingConsoleAuth
}

// newConsoleCommand builds the Console deactivate command and its context from opts.
func newConsoleCommand(opts ConsoleOptions) (*commands.DeactivateCmd, *commands.Context) {
	cmd := &commands.DeactivateCmd{
		URL:  opts.URL,
		UUID: opts.UUID,
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
