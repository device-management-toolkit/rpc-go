/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// WiFiSyncOptions configures WiFi profile synchronization.
type WiFiSyncOptions struct {
	BaseOptions
	// OSWiFiSync enables/disables WiFi profile sync with the host OS.
	OSWiFiSync bool
	// UEFIWiFiSync enables/disables UEFI WiFi profile share (if supported by platform).
	UEFIWiFiSync bool
}

// ConfigureWiFiSync configures WiFi profile synchronization settings.
func ConfigureWiFiSync(opts WiFiSyncOptions) error {
	cmd := &internalcfg.WifiSyncCmd{}
	cmd.OSWiFiSync = opts.OSWiFiSync
	cmd.UEFIWiFiSync = opts.UEFIWiFiSync

	return run(cmd, opts.BaseOptions)
}
