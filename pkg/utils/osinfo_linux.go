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

	"golang.org/x/sys/unix"
)

// GetMEIDriverVersion returns the MEI kernel module version.
// Uses modinfo path when available and falls back to uname release.
func GetMEIDriverVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "modinfo", "-n", "mei_me").Output()
	if err == nil {
		if version, ok := parseMEIModuleVersionFromPath(strings.TrimSpace(string(out))); ok {
			return version
		}
	}

	var uname unix.Utsname

	if err := unix.Uname(&uname); err != nil {
		return ""
	}

	return strings.TrimRight(string(uname.Release[:]), "\x00")
}

func parseMEIModuleVersionFromPath(modulePath string) (string, bool) {
	const modulesPrefix = "/lib/modules/"

	idx := strings.Index(modulePath, modulesPrefix)
	if idx == -1 {
		return "", false
	}

	rest := modulePath[idx+len(modulesPrefix):]

	parts := strings.SplitN(rest, "/", 2)

	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}

	version := parts[0]
	if len(parts) == 1 {
		return version, true
	}

	moduleSubPath := "/" + parts[1]
	if strings.Contains(moduleSubPath, "/updates/") {
		return version + "-updates", true
	}

	if strings.Contains(moduleSubPath, "/extra/") {
		return version + "-extra", true
	}

	return version, true
}
