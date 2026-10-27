/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	internalact "github.com/device-management-toolkit/rpc-go/v2/internal/commands/activate"
)

var errMissingRPSURL = errors.New("RPS server URL is required")

// RemoteOptions configures an AMT activation driven by an RPS server.
type RemoteOptions struct {
	// URL is the RPS WebSocket URL, with the ws or wss scheme (required).
	URL string
	// Profile is the name of the RPS profile to activate with (required).
	Profile string
	// AMTPassword is the device's current AMT admin password, which RPS needs
	// when the device is already activated. If empty in that case, the user
	// will be prompted on stdin.
	AMTPassword string
	// DNSSuffix overrides the DNS suffix reported to RPS.
	DNSSuffix string
	// Hostname overrides the host name reported to RPS.
	Hostname string
	// UUID overrides the device UUID reported to RPS. An overridden UUID
	// prevents the device from connecting to MPS.
	UUID string
	// FriendlyName is the device name reported to RPS.
	FriendlyName string
	// Proxy is the URL of the proxy for the RPS connection. If empty, the proxy
	// from the environment (HTTPS_PROXY, HTTP_PROXY, NO_PROXY) is used.
	Proxy string
	// TLSTunnel provisions TLS on AMT 11 to 18 devices and switches the
	// connection to RPS to an encrypted channel.
	TLSTunnel bool
	// TenantID is the RPS tenant the device belongs to.
	TenantID string
	// SkipCertCheck skips TLS certificate verification when connecting to RPS.
	SkipCertCheck bool
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool
}

// Remote activates AMT on this device as an RPS server directs, like
// "rpc activate --url wss://… --profile <name>". This process relays WSMAN
// messages between RPS and AMT; RPS decides how the device is activated and
// configured.
// If the device is already activated and opts.AMTPassword is empty, the user
// will be prompted on stdin.
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

// validate rejects a URL the command would run in another mode, and a proxy
// URL the RPS client cannot parse.
func (opts RemoteOptions) validate() error {
	if opts.URL == "" {
		return errMissingRPSURL
	}

	// The command fetches a profile from an http(s) URL instead of calling RPS.
	if !isWebSocketURL(opts.URL) {
		return fmt.Errorf("unsupported url scheme: %s", opts.URL)
	}

	// The RPS client panics on a proxy URL it cannot parse.
	if _, err := url.Parse(opts.Proxy); err != nil {
		return fmt.Errorf("invalid Proxy: %w", err)
	}

	return nil
}

// newRemoteCommand builds the remote activate command and its context from opts.
func newRemoteCommand(opts RemoteOptions) (*internalact.ActivateCmd, *commands.Context) {
	cmd := &internalact.ActivateCmd{
		URL:          opts.URL,
		Profile:      opts.Profile,
		DNS:          opts.DNSSuffix,
		Hostname:     opts.Hostname,
		UUID:         opts.UUID,
		FriendlyName: opts.FriendlyName,
		Proxy:        opts.Proxy,
		TLSTunnel:    opts.TLSTunnel,
	}

	ctx := &commands.Context{
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
		SkipCertCheck:    opts.SkipCertCheck,
		TenantID:         opts.TenantID,
	}

	return cmd, ctx
}
