/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// SyncClock synchronizes the host OS clock to AMT.
// Requires the device to be activated and AMT password for WSMAN access.
func SyncClock(opts BaseOptions) error {
	cmd := &internalcfg.SyncClockCmd{}
	return run(cmd, opts)
}
