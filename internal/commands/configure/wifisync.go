/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	log "github.com/sirupsen/logrus"
)

// hasWiFiHardware reports whether the device has a wireless adapter.
// AMT convention: index 0 = wired, index 1 = wireless when present.
func hasWiFiHardware(w interfaces.WSMANer) (bool, error) {
	ports, err := w.GetEthernetSettings()
	if err != nil {
		return false, err
	}

	return len(ports) >= 2 && ports[1].MACAddress != "", nil
}

// WifiSyncCmd represents WiFi port enablement
type WifiSyncCmd struct {
	ConfigureBaseCmd

	// Controls whether AMT WiFi profiles sync with the host OS profiles
	// When true, LocalProfileSynchronizationEnabled will be set to UnrestrictedSync.
	// When false, it will be set to LocalSyncDisabled. Defaults to true for backward compatibility.
	OSWiFiSync bool `help:"Enable/disable WiFi profile sync with OS" name:"oswifisync" default:"true"`

	// Controls whether UEFI <-> WiFi profile share/co-existence is enabled, if the platform supports it.
	// If the platform does not support UEFI WiFi profile share, this flag is ignored by firmware.
	// Defaults to true for backward compatibility.
	UEFIWiFiSync bool `help:"Enable/disable UEFI WiFi profile share (if supported)" name:"uefiwifisync" default:"true"`
}

// Run executes the enable wifi port command
func (cmd *WifiSyncCmd) Run(ctx *commands.Context) error {
	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}

	hasWiFi, err := hasWiFiHardware(cmd.WSMan)
	if err != nil {
		return fmt.Errorf("failed to detect WiFi hardware: %w", err)
	}

	if !hasWiFi {
		log.Warn("Device does not have WiFi hardware; skipping WiFi sync configuration")

		return nil
	}

	// Informational log reflecting desired state
	if cmd.OSWiFiSync {
		log.Info("Setting WiFi sync with OS: ENABLED")
	} else {
		log.Info("Setting WiFi sync with OS: DISABLED")
	}

	if cmd.UEFIWiFiSync {
		log.Info("Setting UEFI WiFi profile share: ENABLED (if supported)")
	} else {
		log.Info("Setting UEFI WiFi profile share: DISABLED")
	}

	// Apply requested WiFi synchronization settings; firmware will always turn WiFi on via state change
	err = cmd.WSMan.EnableWiFi(cmd.OSWiFiSync, cmd.UEFIWiFiSync)
	if err != nil {
		log.Error("Failed to set WiFi sync/profile sharing state.")

		return fmt.Errorf("failed to apply WiFi sync settings: %w", err)
	}

	log.Info("Successfully applied WiFi synchronization settings.")

	return nil
}
