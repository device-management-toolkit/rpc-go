/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package maintenance

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// MaintenanceCmd groups legacy maintenance operations under Kong
// Migrations:
// - syncclock      -> reuse configure.SyncClockCmd
// - syncip         -> reuse configure.WiredCmd with --ipsync or static flags
// - synchostname   -> new implementation in this package
// - syncdeviceinfo -> new implementation in this package
type MaintenanceCmd struct {
	SyncClock      configure.SyncClockCmd `cmd:"" name:"syncclock" help:"Sync the host OS clock to AMT"`
	SyncIP         SyncIPCmd              `cmd:"" name:"syncip" help:"Sync host OS IP configuration to AMT network settings"`
	SyncHostname   SyncHostnameCmd        `cmd:"" name:"synchostname" help:"Sync host OS hostname to AMT"`
	SyncDeviceInfo SyncDeviceInfoCmd      `cmd:"" name:"syncdeviceinfo" help:"Sync device information with remote server"`
}
