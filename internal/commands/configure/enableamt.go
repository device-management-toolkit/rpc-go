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

	// Step 1: Check if AMT operational state change is possible using STATE_INDEPENDENCE_IsChangeToAMTEnabled
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

	// Check if AMT is already enabled (Intel spec: if enabled, continue normal flow)
	if changeEnabled.IsAMTEnabled() {
		log.Info("AMT is already enabled")
		return nil
	}

	// Check if this AMT version supports the SetAmtOperationalState mechanism
	if !changeEnabled.IsNewInterfaceVersion() {
		log.Errorf("This AMT version does not support SetAmtOperationalState mechanism (response: 0x%02X)", uint8(changeEnabled))
		return fmt.Errorf("AMT version does not support SetAmtOperationalState - use legacy provisioning method")
	}

	// Check if transition is allowed in current state
	// Even if not officially allowed, still attempt the operation
	if !changeEnabled.IsTransitionAllowed() {
		reason := changeEnabled.GetTransitionBlockedReason()
		log.Warnf("AMT transition may be blocked (response: 0x%02X): %s", uint8(changeEnabled), reason)
		log.Info("Attempting to enable AMT anyway...")
	} else {
		log.Info("AMT state change is supported and allowed - enabling AMT...")
	}

	// Step 2: Attempt to use MHC_SetAmtOperationalState to enable AMT
	if err := ctx.AMTCommand.EnableAMT(); err != nil {
		log.Error("Failed to enable AMT: ", err)

		// Provide guidance on failure
		if !changeEnabled.IsTransitionAllowed() {
			log.Info("AMT Enable operation failed.")
		}

		return fmt.Errorf("failed to enable AMT: %w", err)
	}

	log.Info("AMT enabled successfully")
	return nil
}
