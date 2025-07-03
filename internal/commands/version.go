/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

// VersionCmd represents the version command
type VersionCmd struct{}

// Run executes the version command
func (cmd *VersionCmd) Run(ctx *Context) error {
	if ctx.JsonOutput {
		// Output version in JSON format using the same structure as the legacy function
		info := map[string]string{
			"app":      strings.ToUpper(utils.ProjectName),
			"version":  utils.ProjectVersion,
			"protocol": utils.ProtocolVersion,
		}

		outBytes, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(outBytes))
	} else {
		// Output version in plain text format matching the legacy function
		fmt.Println(strings.ToUpper(utils.ProjectName))
		fmt.Printf("Version %s\n", utils.ProjectVersion)
		fmt.Printf("Protocol %s\n", utils.ProtocolVersion)
	}

	return nil
}
