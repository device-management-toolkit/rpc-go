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

var errMissingRPSURL = errors.New("RPS server URL is required")

// RemoteOptions configures an AMT deactivation driven by an RPS server.
type RemoteOptions struct {
	// URL is the RPS WebSocket URL, with the ws or wss scheme (required).
	URL string
	// AMTPassword is the device's AMT admin password, which RPS needs to
	// deactivate it. If empty, the user will be prompted on stdin.
	AMTPassword string
	// Force deactivates the device even if MPS does not know it.
	Force bool
	// TLSTunnel switches the connection to RPS to an encrypted channel, in
	// which this process forwards the bytes of AMT's TLS port unchanged.
	TLSTunnel bool
	// TenantID is the RPS tenant the device belongs to.
	TenantID string
	// SkipCertCheck skips TLS certificate verification when connecting to RPS.
	SkipCertCheck bool
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool
}

// Remote deactivates AMT on this device as an RPS server directs, like
// "rpc deactivate --url wss://…". This process relays WSMAN messages between
// RPS and AMT; RPS decides how the device is deactivated.
// If opts.AMTPassword is empty, the user will be prompted on stdin.
// Remote leaves its WebSocket connection to RPS for RPS to close, so a
// long-running program that calls Remote many times holds each connection
// until RPS closes it.
// Requires elevated privileges (admin/root) to access the HECI driver.
func Remote(opts RemoteOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}

	cmd, ctx := newRemoteCommand(opts)

	return run(cmd, ctx)
}

// validate rejects a URL the command would run in another mode, or would
// only reject after AMT access.
func (opts RemoteOptions) validate() error {
	if opts.URL == "" {
		return errMissingRPSURL
	}

	// The command deactivates locally and then calls Console for an http(s) URL.
	if isHTTPURL(opts.URL) {
		return fmt.Errorf("unsupported url scheme: %s; use Console for an http(s) URL", opts.URL)
	}

	if !isWebSocketURL(opts.URL) {
		return fmt.Errorf("unsupported url scheme: %s", opts.URL)
	}

	return nil
}

// newRemoteCommand builds the remote deactivate command and its context from opts.
func newRemoteCommand(opts RemoteOptions) (*commands.DeactivateCmd, *commands.Context) {
	cmd := &commands.DeactivateCmd{
		URL:       opts.URL,
		Force:     opts.Force,
		TLSTunnel: opts.TLSTunnel,
	}

	ctx := &commands.Context{
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
		SkipCertCheck:    opts.SkipCertCheck,
		TenantID:         opts.TenantID,
	}

	return cmd, ctx
}

// isHTTPURL reports whether raw has the http or https scheme, ignoring case,
// the way the deactivate command tells URLs apart.
func isHTTPURL(raw string) bool {
	lower := strings.ToLower(raw)

	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// isWebSocketURL reports whether raw has the ws or wss scheme, ignoring case.
func isWebSocketURL(raw string) bool {
	lower := strings.ToLower(raw)

	return strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://")
}
