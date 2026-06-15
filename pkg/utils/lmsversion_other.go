//go:build !windows && !linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

// GetLMSVersion returns empty on unsupported platforms.
func GetLMSVersion() string {
	return ""
}
