/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func reflectObjectName(v any) string {
	var vName string
	if t := reflect.TypeOf(v); t.Kind() == reflect.Ptr {
		vName = t.Elem().Name()
	} else {
		vName = t.Name()
	}

	return vName
}

func GetTokenFromKeyValuePairs(kvList string, token string) string {
	attributes := strings.Split(kvList, ",")
	tokenMap := make(map[string]string)

	for _, att := range attributes {
		parts := strings.Split(att, "=")
		tokenMap[parts[0]] = parts[1]
	}

	return tokenMap[token]
}

func checkHandleExists(handles map[string]string, cert string) string {
	// get the handle from the map
	for k, v := range handles {
		if v == cert {
			return k
		}
	}

	return ""
}

func (service *ProvisioningService) Pause(howManySeconds int) {
	if howManySeconds <= 0 {
		return
	}

	log.Debugf("pausing %d seconds", howManySeconds)
	time.Sleep(time.Duration(howManySeconds) * time.Second)
}
