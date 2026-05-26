//go:build !windows && !linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

func getKernelVersion() string {
	return ""
}

func getDistro() string {
	return ""
}

func getCPUModel() string {
	return ""
}

// GetMEIDriverVersion returns empty on unsupported platforms.
func GetMEIDriverVersion() string {
	return ""
}

// GetEthernetAdapterCount returns 0 on unsupported platforms.
func GetEthernetAdapterCount() int {
	return 0
}
