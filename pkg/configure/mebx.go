/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// MEBxOptions configures a MEBx password change operation.
type MEBxOptions struct {
	BaseOptions
	// MEBxPassword is the new MEBx password.
	MEBxPassword string
}

// SetMEBx configures the MEBx password.
// Only supported in ACM mode (control mode 2).
func SetMEBx(opts MEBxOptions) error {
	cmd := &internalcfg.MEBxCmd{}
	cmd.MEBxPassword = opts.MEBxPassword

	return run(cmd, opts.BaseOptions)
}
