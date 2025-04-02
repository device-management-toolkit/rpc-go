/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"

	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) SetMebx() (err error) {

	if service.flags.ControlMode != 2 { // If not in ACM, return an error.
		errMsg := "MEBx password can only be configured in ACM. Current device control mode: " + utils.InterpretControlMode(service.flags.ControlMode)
		log.Error(errMsg)
		return utils.SetMEBXPasswordFailed
	}

	// Set up MEBx with the provided password.
	response, err := service.interfacedWsmanMessage.SetupMEBX(service.flags.MEBxPassword)
	log.Trace(response)
	if err != nil {
		log.Error("Failed to configure MEBx Password:", err)
		return err
	}

	log.Info("Successfully configured MEBx Password.")
	return nil
}
