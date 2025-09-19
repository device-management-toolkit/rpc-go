/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package maintenance

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	log "github.com/sirupsen/logrus"
)

// SyncDeviceInfoCmd is a placeholder for syncing device info; actual RPS flow remains legacy
type SyncDeviceInfoCmd struct {
	commands.AMTBaseCmd
}

func (cmd *SyncDeviceInfoCmd) Run(ctx *commands.Context) error {
	// For now, just log that this is a no-op under Kong. Real sync is part of remote flows.
	log.Info("syncdeviceinfo: no-op in Kong path; use remote maintenance flow if needed")

	return nil
}
