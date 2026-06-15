//go:build !windows && !linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

// GetMEIDriverVersion returns empty on unsupported platforms.
func GetMEIDriverVersion() string {
	return ""
}
