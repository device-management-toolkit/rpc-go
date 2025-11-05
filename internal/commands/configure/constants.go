/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package configure

import "errors"

// Error messages
var (
	// ErrDeviceNotActivated indicates the device is not activated and cannot be configured
	ErrDeviceNotActivated = errors.New("device is not activated to configure. Please activate the device first")
)
