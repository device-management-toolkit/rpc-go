/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"errors"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	internalact "github.com/device-management-toolkit/rpc-go/v2/internal/commands/activate"
)

var (
	errInvalidMode = errors.New("must specify either ModeCCM or ModeACM")
	// The command reports these only after reading AMT and prompting for a password.
	errMissingProvisioningCert    = errors.New("provisioning certificate is required for ACM activation")
	errMissingProvisioningCertPwd = errors.New("provisioning certificate password is required for ACM activation")
)

// Mode is the control mode Local activates AMT into.
type Mode int

const (
	// ModeCCM activates AMT in Client Control Mode.
	ModeCCM Mode = iota + 1
	// ModeACM activates AMT in Admin Control Mode, which needs a provisioning
	// certificate that AMT trusts. A device in CCM is upgraded to ACM.
	ModeACM
)

// LocalOptions configures a local AMT activation.
type LocalOptions struct {
	// Mode is the control mode to activate into (required).
	Mode Mode
	// AMTPassword is the AMT admin password to set on the device, or its
	// current password when ModeACM upgrades a device in CCM.
	// If empty, the user will be prompted on stdin, and asked to confirm the
	// password when the device is not activated yet.
	AMTPassword string
	// ProvisioningCert is the base64-encoded PFX provisioning certificate.
	// Required for ModeACM; ignored for ModeCCM.
	ProvisioningCert string
	// ProvisioningCertPassword is the password of ProvisioningCert.
	// Required for ModeACM; ignored for ModeCCM.
	ProvisioningCertPassword string
	// MEBxPassword is the MEBx password to set during ACM activation on AMT 19
	// and later devices that enforce TLS on local ports. If empty and the
	// device needs one, AMTPassword is tried first; if AMT rejects it, the user
	// will be prompted on stdin. Ignored for ModeCCM.
	MEBxPassword string
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool

	// The options below register the device with Console before activation and
	// update its record afterwards. Registration runs when AuthEndpoint is set.

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
	// AuthToken is a bearer token for Console.
	AuthToken string
	// AuthUsername and AuthPassword are exchanged at AuthEndpoint for a bearer
	// token when AuthToken is empty.
	AuthUsername string
	AuthPassword string
	// AuthEndpoint is the absolute Console token exchange URL.
	AuthEndpoint string
	// DevicesEndpoint is the absolute Console devices API URL. If empty,
	// /api/v1/devices on the AuthEndpoint host is used.
	DevicesEndpoint string
}

// Local activates AMT on this device in the control mode opts.Mode selects,
// like "rpc activate --local --ccm" and "rpc activate --local --acm".
// It initializes the AMT hardware interface, detects the control mode,
// registers the device with Console when configured, and activates it.
// If opts.AMTPassword is empty, the user will be prompted on stdin, and asked
// to confirm the password when the device is not activated yet. For ModeACM
// on a device that needs a MEBx password, when opts.MEBxPassword is empty,
// AMTPassword is tried first; if AMT rejects it, the user will be prompted
// on stdin.
// Requires elevated privileges (admin/root) to access the HECI driver.
func Local(opts LocalOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}

	cmd, ctx := newLocalCommand(opts)

	return run(cmd, ctx)
}

// validate rejects options the command rejects only after touching AMT, or not at all.
func (opts LocalOptions) validate() error {
	if opts.Mode != ModeCCM && opts.Mode != ModeACM {
		return errInvalidMode
	}

	if opts.Mode == ModeACM && opts.ProvisioningCert == "" {
		return errMissingProvisioningCert
	}

	if opts.Mode == ModeACM && opts.ProvisioningCertPassword == "" {
		return errMissingProvisioningCertPwd
	}

	// No server URL exists to resolve a relative endpoint against, so registration would be skipped.
	if opts.AuthEndpoint != "" && !isHTTPURL(opts.AuthEndpoint) {
		return errRelativeAuthEndpoint
	}

	return nil
}

// newLocalCommand builds the local activate command and its context from opts.
func newLocalCommand(opts LocalOptions) (*internalact.ActivateCmd, *commands.Context) {
	cmd := &internalact.ActivateCmd{
		Local:               true,
		CCM:                 opts.Mode == ModeCCM,
		ACM:                 opts.Mode == ModeACM,
		ProvisioningCert:    opts.ProvisioningCert,
		ProvisioningCertPwd: opts.ProvisioningCertPassword,
		MEBxPassword:        opts.MEBxPassword,
		UUID:                opts.UUID,
		Hostname:            opts.Hostname,
		FriendlyName:        opts.FriendlyName,
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

// StopConfigurationOptions configures StopConfiguration. It has no fields
// yet; it exists so that options can be added without breaking callers.
type StopConfigurationOptions struct{}

// StopConfiguration moves AMT on this device from the in-provisioning state
// back to pre-provisioning, like "rpc activate --local --stopConfig", so an
// activation that stopped part way can be run again. It needs no AMT password.
// Like the CLI, it prints its result to stdout.
// Requires elevated privileges (admin/root) to access the HECI driver.
func StopConfiguration(opts StopConfigurationOptions) error {
	cmd, ctx := newStopConfigurationCommand(opts)

	return run(cmd, ctx)
}

// newStopConfigurationCommand builds the stop-configuration command and its
// context. StopConfigurationOptions has no fields to map yet.
func newStopConfigurationCommand(StopConfigurationOptions) (*internalact.ActivateCmd, *commands.Context) {
	return &internalact.ActivateCmd{Local: true, StopConfig: true}, &commands.Context{}
}
