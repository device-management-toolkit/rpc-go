//go:build !linux && !windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

// getPlatformOSInfo has no version or distro source on this platform.
func getPlatformOSInfo() OSInfo {
	return OSInfo{}
}
