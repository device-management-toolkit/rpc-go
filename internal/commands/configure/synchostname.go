/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"fmt"
	"os"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// SyncHostnameCmd synchronizes host OS hostname to AMT general settings
type SyncHostnameCmd struct {
	ConfigureBaseCmd
}

// Run executes the hostname sync command
func (cmd *SyncHostnameCmd) Run(ctx *commands.Context) error {
	// Require activated device
	if cmd.GetControlMode() == 0 {
		log.Error(ErrDeviceNotActivated)

		return errors.New(ErrDeviceNotActivated)
	}

	// Retrieve OS hostname and DNS suffix via AMT helpers
	dnsSuffix, err := ctx.AMTCommand.GetOSDNSSuffix()
	if err != nil {
		log.Error(err)
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		log.Error("OS hostname is not available")

		return utils.OSNetworkInterfacesLookupFailed
	}

	// Ensure service availability (optional)
	if _, err := cmd.WSMan.GetGeneralSettings(); err != nil {
		return fmt.Errorf("failed to get general settings: %w", err)
	}

	req := general.GeneralSettingsRequest{}
	if hostname != "" {
		req.HostName = hostname
	}

	if dnsSuffix != "" {
		req.DomainName = dnsSuffix
	}

	if _, err := cmd.WSMan.PutGeneralSettings(req); err != nil {
		return fmt.Errorf("failed to update general settings: %w", err)
	}

	log.Infof("Synchronized AMT hostname to '%s' with DNS suffix '%s'", hostname, dnsSuffix)

	return nil
}
