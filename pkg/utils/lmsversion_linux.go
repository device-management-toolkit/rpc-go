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

const lmsVersionTimeout = 5 * time.Second

// GetLMSVersion attempts to determine the installed LMS version via package managers.
// Falls back through dpkg → rpm → snap.
func GetLMSVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), lmsVersionTimeout)
	defer cancel()

	// Try dpkg (Debian/Ubuntu)
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Version}", "lms").Output()
	if err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			return v
		}
	}

	// Try rpm (RHEL/Fedora/SUSE)
	out, err = exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{VERSION}", "lms").Output()
	if err == nil {
		if v := strings.TrimSpace(string(out)); v != "" && !strings.Contains(v, "not installed") {
			return v
		}
	}

	// Try snap
	out, err = exec.CommandContext(ctx, "snap", "list", "lms").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}

	return ""
}
