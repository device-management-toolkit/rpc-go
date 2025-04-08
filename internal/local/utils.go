/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func GetTokenFromKeyValuePairs(kvList string, token string) string {
	attributes := strings.Split(kvList, ",")
	tokenMap := make(map[string]string)

	for _, att := range attributes {
		parts := strings.Split(att, "=")
		tokenMap[parts[0]] = parts[1]
	}

	return tokenMap[token]
}

func (service *ProvisioningService) Pause(howManySeconds int) {
	if howManySeconds <= 0 {
		return
	}

	log.Debugf("pausing %d seconds", howManySeconds)
	time.Sleep(time.Duration(howManySeconds) * time.Second)
}
