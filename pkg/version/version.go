/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package version

import (
	"runtime"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

// Info holds version and build metadata for the application.
type Info struct {
	App      string `json:"app"`
	Version  string `json:"version"`
	Protocol string `json:"protocol"`
	Commit   string `json:"commit"`
	Date     string `json:"date"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

// Get returns the current version and build information.
func Get() Info {
	return Info{
		App:      utils.ProjectName,
		Version:  utils.ProjectVersion,
		Protocol: utils.ProtocolVersion,
		Commit:   utils.BuildCommit,
		Date:     utils.BuildDate,
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
}
