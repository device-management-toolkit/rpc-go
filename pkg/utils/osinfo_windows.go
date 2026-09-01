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

var (
	lookupExecutable = exec.LookPath
	runCommandOutput = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	}
)

const meiDriverVersionScript = "Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like '*Management Engine Interface*' } | Select-Object -First 1 -ExpandProperty DriverVersion"

func findPowerShellBinary() string {
	for _, candidate := range []string{"powershell", "powershell.exe", "pwsh", "pwsh.exe"} {
		if _, err := lookupExecutable(candidate); err == nil {
			return candidate
		}
	}

	return ""
}

// GetMEIDriverVersion returns the Intel MEI driver version on Windows via WMI.
func GetMEIDriverVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), osInfoTimeout)
	defer cancel()

	psBinary := findPowerShellBinary()
	if psBinary == "" {
		return ""
	}

	out, err := runCommandOutput(ctx, psBinary, "-NoProfile", "-Command", meiDriverVersionScript)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

func getAdapterDHCPEnabled(interfaceName string) *bool {
	ctx, cancel := context.WithTimeout(context.Background(), osInfoTimeout)
	defer cancel()

	psBinary := findPowerShellBinary()
	if psBinary == "" {
		return nil
	}

	name := escapePowerShellSingleQuotedString(interfaceName)
	script := "$idx = (Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionID -eq '" + name + "' -or $_.Name -eq '" + name + "' } | Select-Object -First 1 -ExpandProperty InterfaceIndex); if ($idx -ne $null) { (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"InterfaceIndex=$idx\").DHCPEnabled }"
	out, err := runCommandOutput(ctx, psBinary, "-NoProfile", "-Command", script)
	if err != nil {
		return nil
	}

	switch strings.ToLower(strings.TrimSpace(string(out))) {
	case "true":
		enabled := true
		return &enabled
	case "false":
		enabled := false
		return &enabled
	default:
		return nil
	}
}

func getAdapterDisplayName(interfaceName string) string {
	ctx, cancel := context.WithTimeout(context.Background(), osInfoTimeout)
	defer cancel()

	psBinary := findPowerShellBinary()
	if psBinary == "" {
		return ""
	}

	name := escapePowerShellSingleQuotedString(interfaceName)
	script := "Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionID -eq '" + name + "' -or $_.Name -eq '" + name + "' } | Select-Object -First 1 -ExpandProperty Name"
	out, err := runCommandOutput(ctx, psBinary, "-NoProfile", "-Command", script)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

func escapePowerShellSingleQuotedString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
