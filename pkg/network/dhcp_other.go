//go:build !windows && !linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package network

import "fmt"

func (n *RealOSNetworker) RenewDHCPLease() error {
	return fmt.Errorf("DHCP lease renewal is not supported on this platform")
}
