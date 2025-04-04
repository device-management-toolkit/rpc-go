/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) ChangeAMTPassword() (err error) {
	generalSettings, err := service.interfacedWsmanMessage.GetGeneralSettings()
	if err != nil {
		return err
	}

	challenge := client.AuthChallenge{
		Username: utils.AMTUserName,
		Password: service.flags.NewPassword,
		Realm:    generalSettings.Body.GetResponse.DigestRealm,
	}

	hashedMessage := challenge.HashCredentials()

	bytes, err := hex.DecodeString(hashedMessage)
	if err != nil {
		log.Error("Failed to decode hex string")

		return
	}

	encodedMessage := base64.StdEncoding.EncodeToString(bytes)

	response, err := service.interfacedWsmanMessage.UpdateAMTPassword(encodedMessage)
	log.Trace(response)

	if err != nil {
		log.Error("Failed to updated AMT Password:", err)

		return err
	}

	log.Info("Successfully updated AMT Password.")

	return nil
}
