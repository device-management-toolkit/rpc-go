//go:build !windows && !linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import "fmt"

// IsElevated returns false on unsupported platforms.
func IsElevated() bool {
	return false
}

// SelfElevate is not supported on this platform.
func SelfElevate() error {
	return fmt.Errorf("auto-elevation is not supported on this platform")
}
