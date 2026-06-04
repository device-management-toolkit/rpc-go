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

const osInfoTimeout = 10 * time.Second

// GetMEIDriverVersion returns the Intel MEI driver version on Windows via WMI.
func GetMEIDriverVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), osInfoTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like '*Management Engine Interface*' } | Select-Object -First 1 -ExpandProperty DriverVersion").Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}
