/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	log "github.com/sirupsen/logrus"
)

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

	// Provisioning certificate (for mutual TLS after ACM activation)
	ProvisioningCertFlag    string `help:"Provisioning certificate (base64 encoded)" env:"PROVISIONING_CERT" name:"provisioningCert"`
	ProvisioningCertPwdFlag string `help:"Provisioning certificate password" env:"PROVISIONING_CERT_PASSWORD" name:"provisioningCertPwd"`
}

// Run executes the enable wifi port command
func (cmd *WifiSyncCmd) Run(ctx *commands.Context) error {
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

	// Copy provisioning certificate from flags to base command for mutual TLS
	if cmd.ProvisioningCertFlag != "" {
		cmd.ProvisioningCert = cmd.ProvisioningCertFlag
		cmd.ProvisioningCertPwd = cmd.ProvisioningCertPwdFlag
	}

	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}

	// Apply requested WiFi synchronization settings; firmware will always turn WiFi on via state change
	err := cmd.WSMan.EnableWiFi(cmd.OSWiFiSync, cmd.UEFIWiFiSync)
	if err != nil {
		log.Error("Failed to set WiFi sync/profile sharing state.")

		return fmt.Errorf("failed to apply WiFi sync settings: %w", err)
	}

	log.Info("Successfully applied WiFi synchronization settings.")

	return nil
}
