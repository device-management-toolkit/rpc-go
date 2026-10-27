//go:build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

var osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

func getPlatformOSInfo() OSInfo {
	info := OSInfo{}

	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		info.Version = strings.TrimSpace(unix.ByteSliceToString(uts.Release[:]))
	}

	for _, path := range osReleasePaths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		info.Distro = parseOSReleasePrettyName(f)
		f.Close()

		if info.Distro != "" {
			break
		}
	}

	return info
}
