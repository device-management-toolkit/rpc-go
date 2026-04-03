/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

// VersionCmd represents the version command
type VersionCmd struct{}

// Run executes the version command
func (cmd *VersionCmd) Run(ctx *Context) error {
	goVersion := runtime.Version()
	platform := runtime.GOOS + "/" + runtime.GOARCH

	if ctx.JsonOutput {
		info := map[string]string{
			"app":      strings.ToUpper(utils.ProjectName),
			"version":  utils.ProjectVersion,
			"protocol": utils.ProtocolVersion,
			"commit":   utils.BuildCommit,
			"date":     utils.BuildDate,
			"go":       goVersion,
			"platform": platform,
		}

		outBytes, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(outBytes))
	} else {
		fmt.Print(renderInfoHeader(strings.ToUpper(utils.ProjectName)))
		fmt.Print(renderInfoRow("Version", utils.ProjectVersion))
		fmt.Print(renderInfoRow("Protocol", utils.ProtocolVersion))
		fmt.Print(renderInfoRow("Commit", utils.BuildCommit))
		fmt.Print(renderInfoRow("Built", utils.BuildDate))
		fmt.Print(renderInfoRow("Go", goVersion))
		fmt.Print(renderInfoRow("Platform", platform))
		fmt.Println()
	}

	return nil
}
