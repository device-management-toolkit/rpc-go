//go:build !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// CanAMTBeSupported reports whether the current OS can have MEI/HECI hardware.
// Returns true on platforms where AMT could exist (e.g. Linux with vPro),
// false on platforms where it never will (e.g. macOS).
func CanAMTBeSupported() bool {
	return runtime.GOOS == "linux"
}

// IsElevated returns true if the current process is running as root.
func IsElevated() bool {
	return os.Getuid() == 0
}

// SelfElevate re-launches the current process with root privileges via sudo.
// Uses os.Executable() for the binary path to ensure the exact same binary
// is elevated regardless of PATH differences under sudo.
// This replaces the current process (exec) so it does not return on success.
func SelfElevate() error {
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("sudo not found in PATH: %w", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}

	argv := append([]string{"sudo", exePath}, os.Args[1:]...)

	return syscall.Exec(sudoPath, argv, os.Environ())
}
