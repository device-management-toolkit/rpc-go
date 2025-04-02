//go:build linux
// +build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"os/exec"

	log "github.com/sirupsen/logrus"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
)

func (n *RealOSNetworker) RenewDHCPLease() error {
	log.Debug("renewing DHCP lease")
	cmd := exec.Command("dhclient")
	err := cmd.Run()
	if err != nil {
		log.Error("Error renewing DHCP lease:", err)
		return utils.NetworkConfigurationFailed
	}
	return nil
}
