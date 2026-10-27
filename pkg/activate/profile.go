/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	internalact "github.com/device-management-toolkit/rpc-go/v2/internal/commands/activate"
)

var (
	errProfileSource     = errors.New("exactly one of File and URL must be set")
	errMissingExecutable = errors.New("missing Executable, the path of the rpc binary that runs each profile step")
)

// ProfileOptions configures an AMT activation from a profile.
// Exactly one of File and URL must be set.
type ProfileOptions struct {
	// File is the path of a local profile file, in YAML or encrypted with Key.
	File string
	// URL is a Console profile export URL with the http or https scheme, such
	// as https://console.example.com/api/v1/admin/profiles/export/<name>.
	URL string
	// Key is the 32-byte key that decrypts an encrypted File, or an encrypted
	// profile from URL; for URL it replaces any key the response carries.
	Key string
	// Executable is the path of the rpc binary, built from the same rpc-go
	// version as this package, that runs each profile step (required). A name
	// without a path separator is looked up in PATH.
	Executable string
	// AMTPassword is the device's current AMT admin password, needed when the
	// device is already activated; the run then changes it to the profile's
	// admin password. If it is empty, the user will be prompted on stdin when
	// Console registration reads TLS settings from an activated device. If it
	// is empty or wrong, the user will be prompted on stdin for the current
	// password, up to three times, when a step fails to authenticate.
	AMTPassword string
	// MEBxPassword is the MEBx password ACM activation sets when the profile
	// has none. If both are empty and the device needs one, the activation
	// step tries the AMT password and then prompts on stdin.
	MEBxPassword string
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool

	// The options below configure Console. A profile from URL always registers
	// the device with that Console before activation; a File registers it only
	// when AuthEndpoint is set. Registration also updates the record afterwards.

	// UUID overrides the device GUID read from AMT.
	UUID string
	// Hostname is the device address recorded in Console. If empty, the first
	// non-loopback IPv4 address of this host is used.
	Hostname string
	// FriendlyName is the device name recorded in Console. If empty, the OS
	// host name is used.
	FriendlyName string
	// SkipCertCheck skips TLS certificate verification when connecting to Console.
	SkipCertCheck bool
	// TenantID is the Console tenant the device belongs to.
	TenantID string
	// AuthToken is a bearer token for Console. With URL it also authorizes
	// the profile download.
	AuthToken string
	// AuthUsername and AuthPassword are exchanged for a bearer token when
	// AuthToken is empty.
	AuthUsername string
	AuthPassword string
	// AuthEndpoint is the Console token exchange URL. With File it must be
	// absolute. With URL it may be a path on the URL's host; if empty,
	// /api/v1/authorize and then /mps/login/api/v1/authorize are tried.
	AuthEndpoint string
	// DevicesEndpoint is the absolute Console devices API URL. If empty,
	// /api/v1/devices on the Console host is used.
	DevicesEndpoint string
}

// Profile activates and configures AMT on this device from a profile, like
// "rpc activate --profile <file>" and "rpc activate --url https://…".
//
// As in the CLI, each step (activation, MEBx, AMT features, network, TLS,
// CIRA, proxy) runs as a subprocess, here of opts.Executable. The steps share
// this process's environment, working directory (where rpc reads
// config.yaml), stdin, stdout and stderr: their output is printed, and a step
// that lacks a value it needs prompts on stdin.
//
// When the profile asks for random AMT, MEBx or MPS passwords, they are
// generated during the call and kept only by the device and, when the device
// is registered, by Console; they are not returned.
//
// Requires elevated privileges (admin/root) to access the HECI driver.
func Profile(opts ProfileOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}

	cmd, ctx := newProfileCommand(opts)

	return run(cmd, ctx)
}

// validate rejects options that would leave the profile source ambiguous, run
// another mode, run this process as rpc, or skip Console registration silently.
func (opts ProfileOptions) validate() error {
	if (opts.File == "") == (opts.URL == "") {
		return errProfileSource
	}

	// The command runs RPS activation for a ws(s) URL.
	if opts.URL != "" && !isHTTPURL(opts.URL) {
		return fmt.Errorf("unsupported url scheme: %s", opts.URL)
	}

	// Left empty, every step would run this process's executable as rpc.
	if opts.Executable == "" {
		return errMissingExecutable
	}

	// No server URL exists to resolve a relative endpoint against, so registration would be skipped.
	if opts.File != "" && opts.AuthEndpoint != "" && !isHTTPURL(opts.AuthEndpoint) {
		return errRelativeAuthEndpoint
	}

	return nil
}

// newProfileCommand builds the profile activate command and its context from opts.
func newProfileCommand(opts ProfileOptions) (*internalact.ActivateCmd, *commands.Context) {
	cmd := &internalact.ActivateCmd{
		Profile:      profilePath(opts.File),
		URL:          opts.URL,
		Key:          opts.Key,
		MEBxPassword: opts.MEBxPassword,
		UUID:         opts.UUID,
		Hostname:     opts.Hostname,
		FriendlyName: opts.FriendlyName,
		Executable:   opts.Executable,
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

// profilePath gives a bare file name a directory, because the activate
// command takes a bare name without a profile extension for an RPS profile name.
func profilePath(file string) string {
	if file == "" || strings.ContainsAny(file, `/\`) {
		return file
	}

	return "." + string(filepath.Separator) + file
}
