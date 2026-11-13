/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"bufio"
	"io"
	"runtime"
	"strings"
)

// OSInfo holds host operating system metadata.
type OSInfo struct {
	// Name is the OS family as reported by Go (e.g. "linux", "windows").
	Name string
	// Version is the kernel release on Linux or the full build number on Windows.
	Version string
	// Distro is a human-readable product name (e.g. "Ubuntu 22.04.5 LTS", "Windows 11 Enterprise 24H2").
	Distro string
}

// GetOSInfo returns metadata about the host operating system. Fields that
// cannot be determined are left empty; Name is always populated.
func GetOSInfo() OSInfo {
	info := getPlatformOSInfo()
	info.Name = runtime.GOOS

	return info
}

// parseOSReleasePrettyName returns the PRETTY_NAME value from an os-release file.
func parseOSReleasePrettyName(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"'")
		}
	}

	return ""
}
