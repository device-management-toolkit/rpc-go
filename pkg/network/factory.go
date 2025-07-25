/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package network

// NewOSNetworker returns a platform-specific implementation of OSNetworker
func NewOSNetworker() OSNetworker {
	return &RealOSNetworker{}
}
