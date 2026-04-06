/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// EnableAMT enables the AMT operational state.
// Uses HECI directly; AMT password is not required.
func EnableAMT(opts BaseOptions) error {
	cmd := &internalcfg.EnableAMTCmd{}
	return run(cmd, opts)
}
