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

var (
	lmsLookPath      = exec.LookPath
	lmsCommandOutput = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	}
	lmsGetOSInfo = GetOSInfo
)

// GetLMSVersion attempts to determine the installed LMS version via package managers.
// Uses distro-aware package manager lookup order.
func GetLMSVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), lmsVersionTimeout)
	defer cancel()

	distro := strings.ToLower(lmsGetOSInfo().Distro)

	// Debian/Ubuntu: dpkg first, then snap fallback.
	if strings.Contains(distro, "ubuntu") || strings.Contains(distro, "debian") {
		if v := queryLMSDpkg(ctx); v != "" {
			return v
		}

		return queryLMSSnap(ctx)
	} else if strings.Contains(distro, "rhel") || strings.Contains(distro, "fedora") || strings.Contains(distro, "centos") || strings.Contains(distro, "rocky") || strings.Contains(distro, "alma") || strings.Contains(distro, "suse") {
		// RPM family: rpm first, then snap fallback.
		if v := queryLMSRPM(ctx); v != "" {
			return v
		}

		return queryLMSSnap(ctx)
	} else {
		// Unknown distro: snap, then dpkg, then rpm.
		if v := queryLMSSnap(ctx); v != "" {
			return v
		}

		if v := queryLMSDpkg(ctx); v != "" {
			return v
		}

		return queryLMSRPM(ctx)
	}
}

func queryLMSDpkg(ctx context.Context) string {
	if _, err := lmsLookPath("dpkg-query"); err != nil {
		return ""
	}

	out, err := lmsCommandOutput(ctx, "dpkg-query", "-W", "-f=${Version}", "lms")
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

func queryLMSRPM(ctx context.Context) string {
	if _, err := lmsLookPath("rpm"); err != nil {
		return ""
	}

	out, err := lmsCommandOutput(ctx, "rpm", "-q", "--qf", "%{VERSION}", "lms")
	if err != nil {
		return ""
	}

	v := strings.TrimSpace(string(out))
	if v == "" || strings.Contains(v, "not installed") {
		return ""
	}

	return v
}

func queryLMSSnap(ctx context.Context) string {
	out, err := lmsCommandOutput(ctx, "snap", "list", "lms")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return ""
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return ""
	}

	return fields[1]
}
