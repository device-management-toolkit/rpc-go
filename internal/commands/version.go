/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/version"
)

// VersionCmd represents the version command
type VersionCmd struct{}

// Run executes the version command
func (cmd *VersionCmd) Run(ctx *Context) error {
	info := version.Get()

	if ctx.JsonOutput {
		outBytes, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(outBytes))
	} else {
		fmt.Print(renderInfoHeader(strings.ToUpper(info.App)))
		fmt.Print(renderInfoRow("Version", info.Version))
		fmt.Print(renderInfoRow("Protocol", info.Protocol))
		fmt.Print(renderInfoRow("Commit", info.Commit))
		fmt.Print(renderInfoRow("Built", info.Date))
		fmt.Print(renderInfoRow("Go", info.Go))
		fmt.Print(renderInfoRow("Platform", info.Platform))
		fmt.Println()
	}

	return nil
}
