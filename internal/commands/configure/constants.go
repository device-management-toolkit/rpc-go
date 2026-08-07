/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package configure

import "github.com/device-management-toolkit/rpc-go/v2/pkg/utils"

// Error messages
var (
	// ErrDeviceNotActivated indicates the device is not activated and cannot be
	// configured. It is a utils.CustomError so that subprocess invocations exit
	// with a distinct code (DeviceNotActivated) the orchestrator can match on,
	// rather than the generic failure code — see orchestrator.isDeviceNotActivatedErr.
	ErrDeviceNotActivated = utils.DeviceNotActivated
)
