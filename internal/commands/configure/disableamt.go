/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// DisableAMTCmd represents the disable AMT command
type DisableAMTCmd struct {
	ConfigureBaseCmd
}

// Validate implements Kong's Validate interface for DisableAMT command validation
func (cmd *DisableAMTCmd) Validate() error {
	return cmd.ConfigureBaseCmd.Validate()
}

// Run executes the disable AMT command
// Follows AMT specification:
// 1. Use STATE_INDEPENDENCE_IsChangeToAMTEnabled to check if change is possible
// 2. If transition allowed and AMT enabled, use MHC_SetAmtOperationalState to disable
func (cmd *DisableAMTCmd) Run(ctx *commands.Context) error {
	log.Trace("Disabling AMT...")

	// Step 1: Check if AMT operational state change is possible using STATE_INDEPENDENCE_IsChangeToAMTEnabled
	changeEnabled, err := ctx.AMTCommand.GetChangeEnabled()
	if err != nil {
		log.Errorf("Disable AMT Failed :%v ", err)
		return utils.AMTConnectionFailed
	}

	// Log diagnostic information
	log.Debugf(
		"ChangeEnabled response: 0x%02X | IsNewInterfaceVersion: %t | IsTransitionAllowed: %t | IsAMTEnabled: %t",
		uint8(changeEnabled),
		changeEnabled.IsNewInterfaceVersion(),
		changeEnabled.IsTransitionAllowed(),
		changeEnabled.IsAMTEnabled(),
	)

	// Check if AMT is already disabled
	if !changeEnabled.IsAMTEnabled() {
		log.Info("AMT is already disabled")
		return nil
	}

	// Check if this AMT version supports the SetAmtOperationalState mechanism
	if !changeEnabled.SupportsSetAmtOperationalState() {
		log.Errorf("This AMT version does not support SetAmtOperationalState mechanism (response: 0x%02X)", uint8(changeEnabled))
		return fmt.Errorf("AMT version does not support SetAmtOperationalState - use legacy provisioning method")
	}

	// Check if transition is allowed in current state
	// Even if not officially allowed, still attempt the operation
	if !changeEnabled.IsTransitionAllowed() {
		reason := changeEnabled.GetTransitionBlockedReason()
		log.Warnf("AMT transition blocked (response: 0x%02X): %s", uint8(changeEnabled), reason)

		// Provide specific guidance but proceed anyway for security
		if uint8(changeEnabled)&0xE0 == 0xE0 || uint8(changeEnabled)&0xC0 == 0xC0 {
			log.Info("Note: Device appears provisioned, but attempting disable for security purposes")
		}

		log.Info("Attempting to disable AMT (disable operations are more permissive for security)...")
	} else {
		log.Info("AMT state change is supported and allowed - disabling AMT...")
	}

	// Step 2: Use MHC_SetAmtOperationalState to disable AMT
	if err := ctx.AMTCommand.DisableAMT(); err != nil {
		log.Error("Failed to disable AMT: ", err)
		return fmt.Errorf("failed to disable AMT: %w", err)
	}

	log.Info("AMT disabled successfully")
	return nil
}
