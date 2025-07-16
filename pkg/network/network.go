/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package network

// OSNetworker provides platform-specific network operations
type OSNetworker interface {
	RenewDHCPLease() error
}

// RealOSNetworker is the concrete implementation of OSNetworker
type RealOSNetworker struct{}
