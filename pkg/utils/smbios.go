/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
)

const productUUIDPath = "/sys/class/dmi/id/product_uuid"

const (
	goosLinux   = "linux"
	goosWindows = "windows"
)

var readSMBIOSUUIDFile = os.ReadFile
var currentGOOS = runtime.GOOS
var runSMBIOSUUIDCommand = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return exec.CommandContext(ctx, name, args...).Output()
}

// GetSMBIOSSystemUUID reads the system UUID from OS-exposed SMBIOS sources.
// Returns the UUID as a lowercase RFC 4122 string.
func GetSMBIOSSystemUUID() (string, error) {
	switch currentGOOS {
	case goosLinux:
		// Linux path: read UUID directly from DMI sysfs.
		raw, err := readSMBIOSUUIDFile(productUUIDPath)
		if err != nil {
			return "", fmt.Errorf("failed to read SMBIOS product UUID: %w", err)
		}

		return normalizeUUID(raw)
	case goosWindows:
		return getWindowsUUID()
	default:
		return "", fmt.Errorf("SMBIOS UUID lookup not supported on %s", currentGOOS)
	}
}

func getWindowsUUID() (string, error) {
	out, err := runSMBIOSUUIDCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID")
	if err != nil {
		return "", fmt.Errorf("failed to query UUID on Windows: %w", err)
	}

	return normalizeUUID(out)
}
func normalizeUUID(raw []byte) (string, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		return "", fmt.Errorf("invalid SMBIOS UUID: %w", err)
	}

	normalized := strings.ToLower(parsed.String())
	if isSentinelSMBIOSUUID(normalized) {
		return "", fmt.Errorf("invalid SMBIOS UUID sentinel value")
	}

	return normalized, nil
}

func isSentinelSMBIOSUUID(u string) bool {
	return u == "00000000-0000-0000-0000-000000000000" ||
		u == "ffffffff-ffff-ffff-ffff-ffffffffffff" ||
		u == "03000200-0400-0500-0006-000700080009"
}
