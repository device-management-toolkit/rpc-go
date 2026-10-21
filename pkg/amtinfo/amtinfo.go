/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package amtinfo provides a public API for reading AMT information from the
// local device: what `rpc amtinfo` displays, returned as typed data. Sync also
// pushes the result to a Console devices API, as `rpc amtinfo --sync` does.
package amtinfo

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
)

// Result is the AMT information read by Get or Sync. It marshals to the same
// JSON that `rpc amtinfo --json` prints; fields that were not read are omitted.
type Result = commands.InfoResult

// UserCert is a user certificate stored in AMT. Result.UserCerts keys it by
// its subject's common name, or by its instance ID when it has none.
type UserCert = commands.UserCert

// ProxyAccessPoint is an HTTP proxy access point configured in AMT, listed in
// Result.ProxyAccessPoints.
type ProxyAccessPoint = commands.ProxyAccessPoint

// Options selects what Get reads. The zero value reads what `rpc amtinfo`
// shows by default: everything except certificate hashes and user
// certificates, which are read only when CertificateHashes, UserCertificates
// or All is set. Setting any selection field reads only what is selected.
type Options struct {
	// Version reads the AMT version. With SKU, Result.Features is decoded too.
	Version bool
	// BuildNumber reads the AMT build number.
	BuildNumber bool
	// SKU reads the AMT SKU. With Version, Result.Features is decoded too.
	SKU bool
	// UUID reads the device UUID, falling back to the SMBIOS system UUID when
	// AMT cannot provide it.
	UUID bool
	// UPID reads the Intel Unique Platform ID.
	UPID bool
	// ControlMode reads the AMT control mode.
	ControlMode bool
	// ProvisioningState reads the AMT provisioning state.
	ProvisioningState bool
	// DNSSuffix reads the DNS suffix set in AMT and the OS DNS suffix.
	DNSSuffix bool
	// Hostname reads the OS hostname.
	Hostname bool
	// LAN reads the wired and wireless adapter settings.
	LAN bool
	// RemoteAccess reads the remote access (CIRA) status.
	RemoteAccess bool
	// OperationalState reads whether AMT is enabled in BIOS (AMT 12 and later).
	OperationalState bool
	// CertificateHashes reads the AMT certificate hashes. Not part of the
	// zero value's read.
	CertificateHashes bool
	// UserCertificates reads the user certificates stored in AMT. Not part of
	// the zero value's read.
	UserCertificates bool
	// Proxy reads the HTTP proxy access points configured in AMT.
	Proxy bool
	// All reads everything, including certificate hashes and user certificates.
	All bool

	// AMTPassword is the AMT admin password for the reads that go over WSMAN:
	// the MPS details of RemoteAccess, UserCertificates and Proxy. These need
	// an activated device. Optional: if empty, they use the Local System
	// Account. Get never prompts for it.
	AMTPassword string
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool
}

// SyncOptions configures Sync. Sync always reads all AMT information, as
// `rpc amtinfo --sync` does, so it has no selection fields.
type SyncOptions struct {
	// URL is the absolute URL of the Console devices API, for example
	// https://console.example.com/api/v1/devices. Required.
	URL string
	// AMTPassword is the AMT admin password for the reads that go over WSMAN,
	// as in Options. Optional, and never prompted for.
	AMTPassword string
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool
	// SkipCertCheck skips TLS certificate verification when connecting to Console.
	SkipCertCheck bool
	// TenantID is the Console tenant the device belongs to.
	TenantID string
	// AuthToken is a bearer token for Console.
	AuthToken string
	// AuthUsername and AuthPassword are exchanged for a bearer token when
	// AuthToken is empty. Set both or neither.
	AuthUsername string
	AuthPassword string
	// AuthEndpoint is the token exchange endpoint: an absolute URL, or a path
	// on URL's host. If empty, /api/v1/authorize and then
	// /mps/login/api/v1/authorize are tried. Requires AuthToken, or
	// AuthUsername and AuthPassword.
	AuthEndpoint string
}

// Get reads AMT information from the local device, as `rpc amtinfo` does, and
// returns it instead of printing it. It never prompts. A field that cannot be
// read is left empty and the failure is logged, as in the CLI.
//
// AMT is read through the HECI driver, which needs elevated privileges
// (admin/root). Without HECI, Get returns what the OS provides, with
// Result.HECIAvailable pointing to false, and:
//   - an error matching utils.IncorrectPermissions (use errors.Is) when the
//     process is not elevated: running elevated would read more. The CLI
//     exits with the same error to offer elevation.
//   - a nil error when the process is elevated but HECI is absent, e.g. on
//     hardware without AMT or without the MEI driver.
func Get(opts Options) (*Result, error) {
	cmd, ctx := newCommand(opts)

	return run(cmd, ctx)
}

// Sync reads all AMT information, as Get does with All set, and sends it to
// the Console devices API at opts.URL, as `rpc amtinfo --sync` does. It
// updates the device record with a PATCH; if Console has no record for the
// device, it registers the device as discovered and updates it again.
//
// Invalid options are rejected with the CLI's messages before AMT is read. If
// the sync fails, Sync returns a nil Result and an error starting with
// "device sync failed". Without HECI, Sync syncs what it could read and
// returns it as Get does, with an error matching utils.IncorrectPermissions
// when the process is not elevated. The sync needs the device UUID, which
// without HECI comes from SMBIOS (readable only by root on Linux).
func Sync(opts SyncOptions) (*Result, error) {
	cmd, ctx := newSyncCommand(opts)

	return run(cmd, ctx)
}

// run calls the command's hooks in Kong's order: BeforeApply, Validate (the
// CLI root's ServerAuthFlags, then the command's) and AfterApply. It then
// calls Collect where the CLI calls Run, which would print the result.
func run(cmd *commands.AmtInfoCmd, ctx *commands.Context) (*Result, error) {
	// BeforeApply lets AfterApply degrade, instead of failing, without HECI.
	if err := cmd.BeforeApply(); err != nil {
		return nil, err
	}

	if err := ctx.Validate(); err != nil {
		return nil, err
	}

	// The command's Validate does not use its Kong context.
	if err := cmd.Validate(nil); err != nil {
		return nil, err
	}

	amtCommand := amt.NewAMTCommand()

	if err := cmd.AfterApply(&amtCommand); err != nil {
		return nil, err
	}

	ctx.AMTCommand = &amtCommand

	return cmd.Collect(ctx)
}

// newCommand builds the amtinfo command and its context from opts.
func newCommand(opts Options) (*commands.AmtInfoCmd, *commands.Context) {
	cmd := &commands.AmtInfoCmd{
		Ver:       opts.Version,
		Bld:       opts.BuildNumber,
		Sku:       opts.SKU,
		UUID:      opts.UUID,
		UPID:      opts.UPID,
		Mode:      opts.ControlMode,
		ProvState: opts.ProvisioningState,
		DNS:       opts.DNSSuffix,
		Hostname:  opts.Hostname,
		Lan:       opts.LAN,
		Ras:       opts.RemoteAccess,
		OpState:   opts.OperationalState,
		Cert:      opts.CertificateHashes,
		UserCert:  opts.UserCertificates,
		Proxy:     opts.Proxy,
		All:       opts.All,
	}

	ctx := &commands.Context{
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
	}

	return cmd, ctx
}

// newSyncCommand builds the amtinfo --sync command and its context from opts.
func newSyncCommand(opts SyncOptions) (*commands.AmtInfoCmd, *commands.Context) {
	cmd := &commands.AmtInfoCmd{
		Sync: true,
		URL:  opts.URL,
	}

	ctx := &commands.Context{
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
		SkipCertCheck:    opts.SkipCertCheck,
		TenantID:         opts.TenantID,
		ServerAuthFlags: commands.ServerAuthFlags{
			AuthToken:    opts.AuthToken,
			AuthUsername: opts.AuthUsername,
			AuthPassword: opts.AuthPassword,
			AuthEndpoint: opts.AuthEndpoint,
		},
	}

	return cmd, ctx
}
