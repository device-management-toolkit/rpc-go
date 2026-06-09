//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// GetLMSVersion retrieves the Intel LMS file version from the Windows service binary.
func GetLMSVersion() string {
	// Use PowerShell to query Win32_Service for LMS path and extract FileVersion.
	script := `$p=((Get-WmiObject Win32_Service -Filter "Name='LMS'").PathName -replace '"', '').Split(' ')[0]; (Get-Item $p).VersionInfo.FileVersion`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		log.Debugf("failed to get LMS version on windows: %v", err)
		return ""
	}

	return strings.TrimSpace(string(out))
}
