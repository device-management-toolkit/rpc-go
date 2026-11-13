//go:build !linux && !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

// getPlatformSerialNumber has no SMBIOS source on this platform.
func getPlatformSerialNumber() (string, error) {
	return "", ErrSerialNumberUnavailable
}
