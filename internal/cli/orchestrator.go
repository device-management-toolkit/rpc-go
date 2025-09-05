/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"fmt"
	"strconv"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	internalconfig "github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	ACMMODE = "acmactivate"
)

// ProfileOrchestrator orchestrates the execution of commands from a profile configuration
type ProfileOrchestrator struct {
	config config.Configuration
}

// NewProfileOrchestrator creates a new profile orchestrator
func NewProfileOrchestrator(cfg config.Configuration) *ProfileOrchestrator {
	return &ProfileOrchestrator{config: cfg}
}

// ExecuteProfile orchestrates the execution of all commands based on the profile
func (po *ProfileOrchestrator) ExecuteProfile() error {
	log.Info("Starting profile orchestration...")

	amtCommand := amt.NewAMTCommand()
	if err := amtCommand.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize AMT command: %w", err)
	}

	currentControlMode, err := amtCommand.GetControlMode()
	if err != nil {
		return fmt.Errorf("failed to get current control mode: %w", err)
	}

	if currentControlMode == 0 {
		// Step 1: Activation
		if err := po.executeActivation(); err != nil {
			return fmt.Errorf("activation failed: %w", err)
		}
	} else {
		log.Info("AMT already activated, skipping activation step")
	}

	// wait a sec after activation
	utils.Pause(1)

	// Step 2: MEBx password configuration (ACM only)
	if err := po.executeMEBxConfiguration(); err != nil {
		return fmt.Errorf("MEBx configuration failed: %w", err)
	}

	// Step 3: AMT Features configuration
	if err := po.executeAMTFeaturesConfiguration(); err != nil {
		return fmt.Errorf("AMT features configuration failed: %w", err)
	}

	// Step 4: Wired network configuration
	if err := po.executeWiredNetworkConfiguration(); err != nil {
		return fmt.Errorf("wired network configuration failed: %w", err)
	}

	// Step 5: Enable WiFi port if needed
	if err := po.executeEnableWiFi(); err != nil {
		return fmt.Errorf("WiFi port enable failed: %w", err)
	}

	// Step 6: Wireless profile configurations
	if err := po.executeWirelessConfigurations(); err != nil {
		return fmt.Errorf("wireless configuration failed: %w", err)
	}

	// Step 7: TLS configuration
	if err := po.executeTLSConfiguration(); err != nil {
		return fmt.Errorf("TLS configuration failed: %w", err)
	}

	log.Info("Profile orchestration completed successfully!")

	return nil
}

// executeActivation performs the activation step
func (po *ProfileOrchestrator) executeActivation() error {
	if po.config.Configuration.AMTSpecific.ControlMode == "" {
		log.Info("No activation mode specified, skipping activation")

		return nil
	}

	log.Infof("Executing activation with control mode: %s", po.config.Configuration.AMTSpecific.ControlMode)

	var args []string

	args = append(args, "rpc")
	args = append(args, "activate")

	switch po.config.Configuration.AMTSpecific.ControlMode {
	case ACMMODE:
		args = append(args, "--acm")
		if po.config.Configuration.AMTSpecific.ProvisioningCert != "" {
			args = append(args, "--provisioningCert", po.config.Configuration.AMTSpecific.ProvisioningCert)
		}

		if po.config.Configuration.AMTSpecific.ProvisioningCertPwd != "" {
			args = append(args, "--provisioningCertPwd", po.config.Configuration.AMTSpecific.ProvisioningCertPwd)
		}
	case "ccmactivate":
		args = append(args, "--ccm")
	default:
		return fmt.Errorf("unsupported control mode: %s", po.config.Configuration.AMTSpecific.ControlMode)
	}

	if po.config.Configuration.AMTSpecific.AdminPassword != "" {
		args = append(args, "--password", po.config.Configuration.AMTSpecific.AdminPassword)
	}

	args = append(args, "--local")

	return Execute(args)
}

// executeMEBxConfiguration performs MEBx password configuration
func (po *ProfileOrchestrator) executeMEBxConfiguration() error {
	if po.config.Configuration.AMTSpecific.MEBXPassword == "" ||
		po.config.Configuration.AMTSpecific.ControlMode != ACMMODE {
		log.Info("MEBx password not configured or not in ACM mode, skipping MEBx configuration")

		return nil
	}

	log.Info("Executing MEBx password configuration")

	var args []string

	args = append(args, "rpc")
	args = append(args, "configure", "mebx")

	if po.config.Configuration.AMTSpecific.AdminPassword != "" {
		args = append(args, "--password", po.config.Configuration.AMTSpecific.AdminPassword)
	}

	args = append(args, "--mebxpassword", po.config.Configuration.AMTSpecific.MEBXPassword)

	return Execute(args)
}

// executeAMTFeaturesConfiguration performs AMT features configuration
func (po *ProfileOrchestrator) executeAMTFeaturesConfiguration() error {
	redirection := po.config.Configuration.Redirection

	// Check if any redirection features are configured
	if !redirection.Services.KVM && !redirection.Services.SOL && !redirection.Services.IDER {
		log.Info("No redirection services configured, skipping AMT features configuration")

		return nil
	}

	log.Info("Executing AMT features configuration")

	var args []string

	args = append(args, "rpc")
	args = append(args, "configure", "amtfeatures")

	if po.config.Configuration.AMTSpecific.AdminPassword != "" {
		args = append(args, "--password", po.config.Configuration.AMTSpecific.AdminPassword)
	}

	if redirection.Services.KVM {
		args = append(args, "--kvm")
	}

	if redirection.Services.SOL {
		args = append(args, "--sol")
	}

	if redirection.Services.IDER {
		args = append(args, "--ider")
	}

	// Set user consent if in ACM mode
	if po.config.Configuration.AMTSpecific.ControlMode == ACMMODE {
		switch redirection.UserConsent {
		case "None":
			args = append(args, "--userConsent", "none")
		case "KVM":
			args = append(args, "--userConsent", "kvm")
		default:
			args = append(args, "--userConsent", "all")
		}
	}

	return Execute(args)
}

// executeWiredNetworkConfiguration performs wired network configuration
func (po *ProfileOrchestrator) executeWiredNetworkConfiguration() error {
	wired := po.config.Configuration.Network.Wired

	// Check if wired configuration is needed
	if wired.IPAddress == "" && !wired.DHCPEnabled &&
		wired.PrimaryDNS == "" && wired.SecondaryDNS == "" {
		log.Info("No wired network configuration specified, skipping")

		return nil
	}

	log.Info("Executing wired network configuration")

	var args []string

	args = append(args, "rpc")
	args = append(args, "configure", "wired")

	if po.config.Configuration.AMTSpecific.AdminPassword != "" {
		args = append(args, "--password", po.config.Configuration.AMTSpecific.AdminPassword)
	}

	if wired.DHCPEnabled {
		args = append(args, "--dhcp")
	} else {
		// Static IP configuration
		if wired.IPAddress != "" {
			args = append(args, "--ipaddress", wired.IPAddress)
		}

		if wired.SubnetMask != "" {
			args = append(args, "--subnetmask", wired.SubnetMask)
		}

		if wired.DefaultGateway != "" {
			args = append(args, "--gateway", wired.DefaultGateway)
		}

		if wired.PrimaryDNS != "" {
			args = append(args, "--primarydns", wired.PrimaryDNS)
		}

		if wired.SecondaryDNS != "" {
			args = append(args, "--secondarydns", wired.SecondaryDNS)
		}
	}

	return Execute(args)
}

// executeEnableWiFi enables WiFi port if needed
func (po *ProfileOrchestrator) executeEnableWiFi() error {
	if !po.config.Configuration.Network.Wireless.WiFiSyncEnabled {
		log.Info("WiFi sync not enabled, skipping WiFi port enable")

		return nil
	}

	log.Info("Executing WiFi port enable")

	var args []string

	args = append(args, "rpc")
	args = append(args, "configure", "enablewifiport")

	if po.config.Configuration.AMTSpecific.AdminPassword != "" {
		args = append(args, "--password", po.config.Configuration.AMTSpecific.AdminPassword)
	}

	return Execute(args)
}

// executeWirelessConfigurations performs wireless profile configurations
func (po *ProfileOrchestrator) executeWirelessConfigurations() error {
	if len(po.config.Configuration.Network.Wireless.Profiles) == 0 {
		log.Info("No wireless profiles configured, skipping wireless configuration")

		return nil
	}

	for i, profile := range po.config.Configuration.Network.Wireless.Profiles {
		log.Infof("Executing wireless profile configuration %d/%d: %s", i+1, len(po.config.Configuration.Network.Wireless.Profiles), profile.ProfileName)

		if err := po.executeWirelessProfile(profile); err != nil {
			return fmt.Errorf("failed to configure wireless profile %s: %w", profile.ProfileName, err)
		}
	}

	return nil
}

// executeWirelessProfile configures a single wireless profile
func (po *ProfileOrchestrator) executeWirelessProfile(profile config.WirelessProfile) error {
	var args []string

	args = append(args, "rpc")
	args = append(args, "configure", "wireless")

	if po.config.Configuration.AMTSpecific.AdminPassword != "" {
		args = append(args, "--password", po.config.Configuration.AMTSpecific.AdminPassword)
	}

	args = append(args, "--profileName", profile.ProfileName)
	args = append(args, "--ssid", profile.SSID)
	args = append(args, "--priority", strconv.Itoa(profile.Priority))

	method, success := wifi.ParseAuthenticationMethod(profile.AuthenticationMethod)
	if !success {
		return fmt.Errorf("invalid authentication method: %s", profile.AuthenticationMethod)
	}

	args = append(args, "--authenticationMethod", strconv.Itoa((int)(method)))

	encryptionMethod, success := wifi.ParseEncryptionMethod(profile.EncryptionMethod)
	if !success {
		return fmt.Errorf("invalid encryption method: %s", profile.EncryptionMethod)
	}

	args = append(args, "--encryptionMethod", strconv.Itoa((int)(encryptionMethod)))

	// Add PSK passphrase if provided
	if profile.Password != "" {
		args = append(args, "--pskPassphrase", profile.Password)
	}

	// Add 802.1x settings if configured
	if profile.IEEE8021x != nil {
		ieee := profile.IEEE8021x
		args = append(args, "--ieee8021xProfileName", fmt.Sprintf("%s_8021x", profile.ProfileName))

		if ieee.Username != "" {
			args = append(args, "--ieee8021xUsername", ieee.Username)
		}

		if ieee.Password != "" {
			args = append(args, "--ieee8021xPassword", ieee.Password)
		}

		if ieee.AuthenticationProtocol != 0 {
			args = append(args, "--ieee8021xAuthenticationProtocol", strconv.Itoa(ieee.AuthenticationProtocol))
		}

		if ieee.PrivateKey != "" {
			args = append(args, "--ieee8021xPrivateKey", ieee.PrivateKey)
		}

		if ieee.ClientCert != "" {
			args = append(args, "--ieee8021xClientCert", ieee.ClientCert)
		}

		if ieee.CACert != "" {
			args = append(args, "--ieee8021xCACert", ieee.CACert)
		}
	}

	return Execute(args)
}

// executeTLSConfiguration performs TLS configuration
func (po *ProfileOrchestrator) executeTLSConfiguration() error {
	if !po.config.Configuration.TLS.Enabled {
		log.Info("TLS not enabled, skipping TLS configuration")

		return nil
	}

	log.Info("Executing TLS configuration")

	var args []string

	args = append(args, "rpc")
	args = append(args, "configure", "tls")

	if po.config.Configuration.AMTSpecific.AdminPassword != "" {
		args = append(args, "--password", po.config.Configuration.AMTSpecific.AdminPassword)
	}

	// Determine TLS mode
	var mode string

	if po.config.Configuration.TLS.MutualAuthentication {
		if po.config.Configuration.TLS.AllowNonTLS {
			mode = "MutualAndNonTLS"
		} else {
			mode = "Mutual"
		}
	} else {
		if po.config.Configuration.TLS.AllowNonTLS {
			mode = "ServerAndNonTLS"
		} else {
			mode = "Server"
		}
	}

	args = append(args, "--mode", mode)

	if po.config.Configuration.TLS.SigningAuthority == "SelfSigned" {
	} else {
		// Add Enterprise Assistant settings if configured
		if po.config.Configuration.EnterpriseAssistant.URL != "" {
			args = append(args, "--eaAddress", po.config.Configuration.EnterpriseAssistant.URL)
			if po.config.Configuration.EnterpriseAssistant.Username != "" {
				args = append(args, "--eaUsername", po.config.Configuration.EnterpriseAssistant.Username)
			}

			if po.config.Configuration.EnterpriseAssistant.Password != "" {
				args = append(args, "--eaPassword", po.config.Configuration.EnterpriseAssistant.Password)
			}
		}
	}

	return Execute(args)
}

// ExecuteProfile is a helper function to execute a profile from a file path
func ExecuteProfile(profilePath string) error {
	// Load configuration from profile
	cfg, err := internalconfig.LoadConfig(profilePath)
	if err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	// Create profile orchestrator
	orchestrator := NewProfileOrchestrator(cfg)

	// Execute the profile
	return orchestrator.ExecuteProfile()
}
