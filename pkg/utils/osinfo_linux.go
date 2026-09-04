/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var meiModulePathRegex = regexp.MustCompile(`.*/lib/modules/([^/]+)/(.*)`)

var (
	runModinfo = func(ctx context.Context, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "modinfo", args...).Output()
	}
	getKernelRelease = func() string {
		var uname unix.Utsname

		if err := unix.Uname(&uname); err != nil {
			return ""
		}

		return strings.TrimRight(string(uname.Release[:]), "\x00")
	}
)

// GetMEIDriverVersion returns the MEI kernel module version.
// Prefers explicit module version and falls back to module path / kernel release.
func GetMEIDriverVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := runModinfo(ctx, "-F", "version", "mei_me")
	if err == nil {
		if version := strings.TrimSpace(string(out)); version != "" {
			return version
		}
	}

	out, err = runModinfo(ctx, "-n", "mei_me")
	if err == nil {
		if version, ok := parseMEIModuleVersionFromPath(strings.TrimSpace(string(out))); ok {
			return version
		}
	}

	return getKernelRelease()
}

func parseMEIModuleVersionFromPath(modulePath string) (string, bool) {
	matches := meiModulePathRegex.FindStringSubmatch(modulePath)
	if len(matches) != 3 || matches[1] == "" {
		return "", false
	}

	version := matches[1]
	moduleSubPath := "/" + matches[2]

	if strings.Contains(moduleSubPath, "/updates/") {
		return version + "-updates", true
	}

	if strings.Contains(moduleSubPath, "/extra/") {
		return version + "-extra", true
	}

	return version, true
}

func getAdapterDHCPEnabled(interfaceName string) *bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "nmcli", "-g", "GENERAL.CONNECTION", "device", "show", interfaceName).Output()
	if err != nil {
		return nil
	}

	connectionName := strings.TrimSpace(string(out))
	if connectionName == "" || connectionName == "--" {
		return nil
	}

	out, err = exec.CommandContext(ctx, "nmcli", "-g", "ipv4.method", "connection", "show", connectionName).Output()
	if err != nil {
		return nil
	}

	method := strings.ToLower(strings.TrimSpace(string(out)))
	if method == "" {
		return nil
	}

	enabled := method == "auto"

	return &enabled
}

func getAdapterDisplayName(interfaceName string) string {
	devicePath, err := os.Readlink(filepath.Join("/sys/class/net", interfaceName, "device"))
	if err != nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "lspci", "-D", "-s", filepath.Base(devicePath)).Output()
	if err != nil {
		return ""
	}

	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return ""
	}

	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), fields[0]))
}
