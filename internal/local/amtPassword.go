/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	// GetGeneralSettingsRetryDelay is the duration to wait before retrying GetGeneralSettings
	// after an EOF or connection error. AMT 20/21 may need a moment after WSMAN client setup
	// before accepting requests.
	GetGeneralSettingsRetryDelay = 1 * time.Second
)

func (service *ProvisioningService) ChangeAMTPassword() (err error) {
	generalSettings, err := service.interfacedWsmanMessage.GetGeneralSettings()
	if err != nil {
		// AMT 20/21 may need a moment after WSMAN client setup before accepting requests
		// Retry once if we get EOF or connection error
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection") {
			log.Debug("First GetGeneralSettings failed, retrying...")
			time.Sleep(GetGeneralSettingsRetryDelay)

			generalSettings, err = service.interfacedWsmanMessage.GetGeneralSettings()
			if err != nil {
				return err
			}
		} else {
			return err
		}
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

		return err
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
