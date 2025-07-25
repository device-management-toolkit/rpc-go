//go:build !windows
// +build !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package network

import (
	"context"
	"os/exec"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (n *RealOSNetworker) RenewDHCPLease() error {
	log.Debug("renewing DHCP lease")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dhclient")

	err := cmd.Run()
	if err != nil {
		log.Error("Error renewing DHCP lease:", err)

		return utils.NetworkConfigurationFailed
	}

	return nil
}
