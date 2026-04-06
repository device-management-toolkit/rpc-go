/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// SyncHostname synchronizes the host OS hostname and DNS suffix to AMT general settings.
// Requires the device to be activated and AMT password for WSMAN access.
func SyncHostname(opts BaseOptions) error {
	cmd := &internalcfg.SyncHostnameCmd{}
	return run(cmd, opts)
}
