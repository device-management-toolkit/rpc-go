/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// AMTPasswordOptions configures an AMT password change operation.
type AMTPasswordOptions struct {
	BaseOptions
	// NewPassword is the new AMT admin password.
	NewPassword string
}

// ChangeAMTPassword changes the AMT admin password.
// Requires the device to be activated and current AMT password for WSMAN access.
func ChangeAMTPassword(opts AMTPasswordOptions) error {
	cmd := &internalcfg.AMTPasswordCmd{}
	cmd.NewPassword = opts.NewPassword

	return run(cmd, opts.BaseOptions)
}
