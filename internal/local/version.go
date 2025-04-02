/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
)

type VersionInfo struct {
	App      string `json:"app"`
	Version  string `json:"version"`
	Protocol string `json:"protocol"`
}

func (service *ProvisioningService) DisplayVersion() (err error) {
	if service.flags.JsonOutput {
		info := VersionInfo{
			App:      strings.ToUpper(utils.ProjectName),
			Version:  utils.ProjectVersion,
			Protocol: utils.ProtocolVersion,
		}

		outBytes, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return err
		}

		println(string(outBytes))
	} else {
		fmt.Println(strings.ToUpper(utils.ProjectName))
		fmt.Println("Version", utils.ProjectVersion)
		fmt.Println("Protocol", utils.ProtocolVersion)
	}

	return nil
}
