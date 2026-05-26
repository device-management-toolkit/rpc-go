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
)

// DetectMonitorConnected checks if a physical monitor is connected.
// Uses WMI Win32_DesktopMonitor to detect active monitors.
func DetectMonitorConnected() *bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"Get-CimInstance -ClassName Win32_DesktopMonitor | Where-Object { $_.Availability -eq 3 } | Measure-Object | Select-Object -ExpandProperty Count")

	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	count := strings.TrimSpace(string(out))
	connected := count != "" && count != "0"

	return &connected
}
