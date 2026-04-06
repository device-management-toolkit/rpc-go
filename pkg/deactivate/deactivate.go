/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package deactivate provides a public API for local AMT deactivation.
package deactivate

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
)

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
}

// Run performs a local AMT deactivation.
// It initializes the AMT hardware interface, detects the control mode,
// sets up the WSMAN connection, and deactivates the device.
// Requires elevated privileges (admin/root) to access the HECI driver.
func Run(opts Options) error {
	amtCommand := amt.NewAMTCommand()

	commands.DefaultSkipAMTCertCheck = opts.SkipAMTCertCheck

	cmd := &commands.DeactivateCmd{}
	cmd.Local = true
	cmd.PartialUnprovision = opts.PartialUnprovision

	if err := cmd.AfterApply(&amtCommand); err != nil {
		return err
	}

	ctx := &commands.Context{
		AMTCommand:       &amtCommand,
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
	}

	return cmd.Run(ctx)
}
