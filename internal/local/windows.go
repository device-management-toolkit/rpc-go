//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package local

import (
	"os/exec"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (n *RealOSNetworker) RenewDHCPLease() error {
	log.Debug("renewing DHCP lease")

	cmd := exec.Command("ipconfig", "/renew")

	err := cmd.Run()
	if err != nil {
		log.Error("Error renewing DHCP lease:", err)

		return utils.WiredConfigurationFailed
	}

	return nil
}
