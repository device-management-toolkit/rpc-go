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
	log.Trace("Enabling AMT...")

	// Step 1: Check if AMT operational state change is possible using STATE_INDEPENDENCE_IsChangeToAMTEnabled
	changeEnabled, err := ctx.AMTCommand.GetChangeEnabled()
	if err != nil {
		log.Error("Failed to get change enabled status: ", err)

		return utils.AMTConnectionFailed
	}

	// Log diagnostic information
	operationalStateLabel := "Disabled"
	if changeEnabled.IsAMTEnabled() {
		operationalStateLabel = "Enabled"
	}

	log.WithFields(log.Fields{
		"transitionAllowed":       changeEnabled.IsTransitionAllowed(),
		"currentOperationalState": operationalStateLabel,
		"isNewInterfaceVersion":   changeEnabled.IsNewInterfaceVersion(),
	}).Debugf("IsAMTChangeEnabled response: 0x%02X", uint8(changeEnabled))

	// Check if AMT is already enabled (Intel spec: if enabled, continue normal flow)
	if changeEnabled.IsAMTEnabled() {
		log.Info("AMT is already enabled")

		return nil
	}

	// Check if this AMT version supports the SetAmtOperationalState mechanism
	if !changeEnabled.SupportsSetAmtOperationalState() {
		log.Error("AMT does not support SetAmtOperationalState")

		return fmt.Errorf("AMT version does not support SetAmtOperationalState - use legacy provisioning method")
	}

	// Check if transition is allowed in current state
	// Even if not officially allowed, still attempt the operation
	if !changeEnabled.IsTransitionAllowed() {
		reason := changeEnabled.GetTransitionBlockedReason()
		log.WithFields(log.Fields{
			"reason": reason,
		}).Warn("AMT transition may be blocked; attempting to enable anyway")
	} else {
		log.Info("AMT state change allowed; enabling AMT")
	}

	// Step 2: Attempt to use MHC_SetAmtOperationalState to enable AMT
	if err := ctx.AMTCommand.EnableAMT(); err != nil {
		return fmt.Errorf("failed to enable AMT; retry after rebooting the device: %w", err)
	}

	log.Info("AMT enabled successfully")

	return nil
}
