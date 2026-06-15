//go:build !windows && !linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

// DetectMonitorConnected returns nil on unsupported platforms.
func DetectMonitorConnected() *bool {
	return nil
}
