/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// EnableAMTCmd represents the enable AMT command
type EnableAMTCmd struct {
	ConfigureBaseCmd
}

// Validate implements Kong's Validate interface for EnableAMT command validation
func (cmd *EnableAMTCmd) Validate() error {
	return cmd.ConfigureBaseCmd.Validate()
}

// Run executes the enable AMT command
func (cmd *EnableAMTCmd) Run(ctx *commands.Context) error {
	log.Info("Enabling AMT...")

	// Check if AMT can be enabled
	changeEnabled, err := ctx.AMTCommand.GetChangeEnabled()
	if err != nil {
		log.Error("Failed to get change enabled status: ", err)
		return utils.AMTConnectionFailed
	}

	// Log diagnostic information
	log.Debugf("ChangeEnabled response: 0x%02X", uint8(changeEnabled))
	log.Debugf("IsNewInterfaceVersion: %t", changeEnabled.IsNewInterfaceVersion())
	log.Debugf("IsTransitionAllowed: %t", changeEnabled.IsTransitionAllowed())
	log.Debugf("IsAMTEnabled: %t", changeEnabled.IsAMTEnabled())

	// Check if this AMT version supports SetAmtOperationalState
	if !changeEnabled.IsNewInterfaceVersion() {
		log.Warnf("This AMT version may not support SetAmtOperationalState command (response: 0x%02X)", uint8(changeEnabled))
		log.Info("Attempting to enable AMT anyway...")
	}

	// Check if AMT is already enabled
	if changeEnabled.IsAMTEnabled() {
		log.Info("AMT is already enabled")
		return nil
	}

	// Warn about transition state but attempt anyway
	if !changeEnabled.IsTransitionAllowed() {
		log.Warnf("AMT transition may not be allowed in current state (response: 0x%02X)", uint8(changeEnabled))
		log.Info("This typically means the device is not in unprovisioned state")
		log.Info("Attempting to enable AMT anyway...")
	}

	// Enable AMT
	if err := ctx.AMTCommand.EnableAMT(); err != nil {
		log.Error("Failed to enable AMT: ", err)
		return fmt.Errorf("failed to enable AMT: %w", err)
	}

	log.Info("AMT enabled successfully")
	return nil
}