/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	log "github.com/sirupsen/logrus"
)

// EnableWifiPortCmd represents WiFi port enablement
type EnableWifiPortCmd struct {
	ConfigureBaseCmd
}

// Run executes the enable wifi port command
func (cmd *EnableWifiPortCmd) Run(ctx *commands.Context) error {
	log.Info("Enabling WiFi port and local profile synchronization...")

	// Enable WiFi port with sync and sharing enabled
	err := cmd.WSMan.EnableWiFi(true, true)
	if err != nil {
		log.Error("Failed to enable wifi port and local profile synchronization.")

		return fmt.Errorf("failed to enable WiFi port: %w", err)
	}

	log.Info("Successfully enabled wifi port and local profile synchronization.")

	return nil
}
