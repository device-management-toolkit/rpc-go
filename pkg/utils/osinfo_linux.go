/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"strings"

	"golang.org/x/sys/unix"
)

// GetMEIDriverVersion returns the MEI kernel module version.
// On Linux, MEI is an in-tree module so its version is the kernel version.
func GetMEIDriverVersion() string {
	var uname unix.Utsname

	if err := unix.Uname(&uname); err != nil {
		return ""
	}

	return strings.TrimRight(string(uname.Release[:]), "\x00")
}
