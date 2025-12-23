/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"
	"net"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	log "github.com/sirupsen/logrus"
)

// WiredCmd represents ethernet configuration
type WiredCmd struct {
	ConfigureBaseCmd

	// 802.1x settings
	IEEE8021xProfileName            string `help:"802.1x profile name" name:"ieee8021xProfileName"`
	IEEE8021xUsername               string `help:"802.1x username" alias:"username" name:"ieee8021xUsername"`
	IEEE8021xPassword               string `help:"802.1x password" name:"ieee8021xPassword"`
	IEEE8021xAuthenticationProtocol int    `help:"802.1x authentication protocol (0=EAP-TLS, 2=PEAPv0/EAP-MSCHAPv2)" alias:"authenticationprotocol" enum:"0,2" default:"0" name:"ieee8021xAuthenticationProtocol"`
	IEEE8021xPrivateKey             string `help:"802.1x private key (PEM format)" alias:"privatekey" name:"ieee8021xPrivateKey"`
	IEEE8021xClientCert             string `help:"802.1x client certificate (PEM format)" alias:"clientcert" name:"ieee8021xClientCert"`
	IEEE8021xCACert                 string `help:"802.1x CA certificate (PEM format)" alias:"cacert" name:"ieee8021xCACert"`

	// Enterprise Assistant settings
	EAAddress  string `help:"Enterprise Assistant address" name:"eaAddress"`
	EAUsername string `help:"Enterprise Assistant username" name:"eaUsername"`
	EAPassword string `help:"Enterprise Assistant password" name:"eaPassword"`

	// Ethernet settings
	DHCPEnabled   *bool  `help:"Enable DHCP" name:"dhcp"`
	IPSyncEnabled bool   `help:"Enable IP Sync with host OS" name:"ipsync"`
	IPAddress     string `help:"Static IP address" name:"ipaddress"`
	SubnetMask    string `help:"Subnet mask" name:"subnetmask"`
	Gateway       string `help:"Default gateway" name:"gateway"`
	PrimaryDNS    string `help:"Primary DNS server" name:"primarydns"`
	SecondaryDNS  string `help:"Secondary DNS server" name:"secondarydns"`

	// Provisioning certificate (for mutual TLS after ACM activation)
	ProvisioningCertFlag    string `help:"Provisioning certificate (base64 encoded)" env:"PROVISIONING_CERT" name:"provisioningCert"`
	ProvisioningCertPwdFlag string `help:"Provisioning certificate password" env:"PROVISIONING_CERT_PASSWORD" name:"provisioningCertPwd"`
}

// Validate implements Kong's Validate interface for MEBx command validation
func (cmd *WiredCmd) Validate() error {
	// First call the base Validate to handle password validation
	if err := cmd.ConfigureBaseCmd.Validate(); err != nil {
		return err
	}

	// Validate DHCP vs static IP configuration
	dhcpEnabled := cmd.DHCPEnabled != nil && *cmd.DHCPEnabled
	staticIPProvided := cmd.IPAddress != "" || cmd.SubnetMask != "" || cmd.Gateway != "" || cmd.PrimaryDNS != "" || cmd.SecondaryDNS != ""

	// Require explicit choice between DHCP or static configuration
	if !dhcpEnabled && !staticIPProvided {
		return fmt.Errorf("must specify -dhcp or static IP settings (ipaddress, subnetmask, gateway, primarydns)")
	}

	if dhcpEnabled && staticIPProvided {
		return fmt.Errorf("cannot specify static IP settings when DHCP is enabled")
	}

	if !dhcpEnabled && staticIPProvided {
		// Validate static IP settings are complete
		if cmd.IPAddress == "" {
			return fmt.Errorf("IP address is required for static configuration")
		}

		if cmd.SubnetMask == "" {
			return fmt.Errorf("subnet mask is required for static configuration")
		}

		if cmd.Gateway == "" {
			return fmt.Errorf("gateway is required for static configuration")
		}

		if cmd.PrimaryDNS == "" {
			return fmt.Errorf("primary DNS is required for static configuration")
		}

		// Validate IP address formats
		if net.ParseIP(cmd.IPAddress) == nil {
			return fmt.Errorf("invalid IP address format: %s", cmd.IPAddress)
		}

		if net.ParseIP(cmd.SubnetMask) == nil {
			return fmt.Errorf("invalid subnet mask format: %s", cmd.SubnetMask)
		}

		if net.ParseIP(cmd.Gateway) == nil {
			return fmt.Errorf("invalid gateway format: %s", cmd.Gateway)
		}

		if net.ParseIP(cmd.PrimaryDNS) == nil {
			return fmt.Errorf("invalid primary DNS format: %s", cmd.PrimaryDNS)
		}

		if cmd.SecondaryDNS != "" && net.ParseIP(cmd.SecondaryDNS) == nil {
			return fmt.Errorf("invalid secondary DNS format: %s", cmd.SecondaryDNS)
		}
	}

	return nil
}

// Run executes the wired configuration command
func (cmd *WiredCmd) Run(ctx *commands.Context) error {
	// Copy provisioning certificate from flags to base command for mutual TLS
	if cmd.ProvisioningCertFlag != "" {
		cmd.ProvisioningCert = cmd.ProvisioningCertFlag
		cmd.ProvisioningCertPwd = cmd.ProvisioningCertPwdFlag
	}

	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}

	log.Info("Configuring wired ethernet settings...")

	// Add defer for error cleanup similar to old code
	defer func() {
		// If there's an error during 802.1x configuration, clean up certificates
		// This will be called at the end of the function
	}()

	// Get the current ethernet settings
	getResponse, err := cmd.WSMan.GetEthernetSettings()
	if err != nil {
		return fmt.Errorf("failed to get current ethernet settings: %w", err)
	}

	if len(getResponse) == 0 {
		return fmt.Errorf("no ethernet settings found")
	}

	// Create the request for the new settings based on current settings
	settingsRequest := cmd.createEthernetSettingsRequest(getResponse[0])

	// Update the ethernet settings in AMT
	_, err = cmd.WSMan.PutEthernetSettings(settingsRequest, settingsRequest.InstanceID)
	if err != nil {
		return fmt.Errorf("failed to configure ethernet settings: %w", err)
	}

	// For now, disable any existing 802.1x profile (simple implementation)
	err = cmd.disable8021xProfile()
	if err != nil {
		log.Warnf("Failed to disable 802.1x profile: %v", err)
		// Don't fail the entire operation for this
	}

	// Check to configure 802.1x - only if profile name is provided
	if cmd.IEEE8021xProfileName == "" {
		log.Info("Wired settings configured successfully")

		return nil
	}

	// Configure 802.1x
	err = cmd.configure8021x()
	if err != nil {
		return fmt.Errorf("failed to configure 802.1x: %w", err)
	}

	// TODO: Implement Enterprise Assistant configuration if EA settings are provided
	if cmd.EAAddress != "" {
		log.Warn("Enterprise Assistant configuration not yet implemented in this command")
	}

	log.Info("Wired settings configured with 802.1x successfully")

	return nil
}

// createEthernetSettingsRequest creates an ethernet settings request based on current settings and command parameters
func (cmd *WiredCmd) createEthernetSettingsRequest(getResponse ethernetport.SettingsResponse) ethernetport.SettingsRequest {
	settingsRequest := ethernetport.SettingsRequest{
		XMLName:        getResponse.XMLName,
		H:              "",
		ElementName:    getResponse.ElementName,
		InstanceID:     getResponse.InstanceID,
		SharedMAC:      getResponse.SharedMAC,
		SharedStaticIp: getResponse.SharedStaticIp,
		IpSyncEnabled:  getResponse.IpSyncEnabled,
		DHCPEnabled:    getResponse.DHCPEnabled,
		IPAddress:      getResponse.IPAddress,
		SubnetMask:     getResponse.SubnetMask,
		DefaultGateway: getResponse.DefaultGateway,
		PrimaryDNS:     getResponse.PrimaryDNS,
		SecondaryDNS:   getResponse.SecondaryDNS,
	}

	// Determine configuration mode
	dhcpEnabled := cmd.DHCPEnabled != nil && *cmd.DHCPEnabled
	staticIPProvided := cmd.IPAddress != "" || cmd.SubnetMask != "" || cmd.Gateway != "" || cmd.PrimaryDNS != "" || cmd.SecondaryDNS != ""
	/**
	 * CONFIGURATION | DHCPEnabled | IpSyncEnabled | SharedStaticIp | IPAddress | SubnetMask | DefaultGwy | PrimaryDNS | SecondaryDNS
	 * ------------------------------------------------------------------------------------------------------------------------------------------------
	 *     DHCP      | TRUE        | TRUE          | FALSE          | NULL      | NULL       | NULL       | NULL       | NULL
	 * ------------------------------------------------------------------------------------------------------------------------------------------------
	 *   Static IP   | FALSE       | FALSE         | FALSE          | Required  | Required   | Optional   | Optional   | Optional
	 *   Static IP   | FALSE       | TRUE          | TRUE           | NULL      | NULL       | NULL       | NULL       | NULL
	 * ------------------------------------------------------------------------------------------------------------------------------------------------
	 */
	if dhcpEnabled {
		// DHCP mode
		settingsRequest.DHCPEnabled = true
		settingsRequest.IpSyncEnabled = true
		settingsRequest.SharedStaticIp = false
	} else if staticIPProvided {
		// Static IP mode
		settingsRequest.DHCPEnabled = false
		settingsRequest.IpSyncEnabled = cmd.IPSyncEnabled
		// SharedStaticIp follows IpSyncEnabled
		settingsRequest.SharedStaticIp = settingsRequest.IpSyncEnabled

		// Set static IP settings
		settingsRequest.IPAddress = cmd.IPAddress
		settingsRequest.SubnetMask = cmd.SubnetMask
		settingsRequest.DefaultGateway = cmd.Gateway
		settingsRequest.PrimaryDNS = cmd.PrimaryDNS
		settingsRequest.SecondaryDNS = cmd.SecondaryDNS
	}

	if settingsRequest.IpSyncEnabled || settingsRequest.DHCPEnabled {
		settingsRequest.IPAddress = ""
		settingsRequest.SubnetMask = ""
		settingsRequest.DefaultGateway = ""
		settingsRequest.PrimaryDNS = ""
		settingsRequest.SecondaryDNS = ""
	}

	return settingsRequest
}

// disable8021xProfile disables any existing 802.1x profile
func (cmd *WiredCmd) disable8021xProfile() error {
	response, err := cmd.WSMan.GetIPSIEEE8021xSettings()
	if err != nil {
		return err
	}

	// Enabled(2), Disabled(3), Enabled without certificates(6)
	if response.Body.IEEE8021xSettingsResponse.Enabled != 3 {
		request := ieee8021x.IEEE8021xSettingsRequest{
			ElementName: response.Body.IEEE8021xSettingsResponse.ElementName,
			InstanceID:  response.Body.IEEE8021xSettingsResponse.InstanceID,
			Enabled:     3,
		}

		_, err = cmd.WSMan.PutIPSIEEE8021xSettings(request)
		if err != nil {
			return err
		}

		// Delete unused certificates
		certs.PruneCerts(cmd.WSMan)
	}

	return nil
}

// configure8021x configures IEEE 802.1x settings for wired ethernet
func (cmd *WiredCmd) configure8021x() error {
	log.Infof("Configuring 802.1x profile: %s", cmd.IEEE8021xProfileName)

	// TODO: Add Enterprise Assistant support similar to old code
	if cmd.EAAddress != "" {
		log.Warn("Enterprise Assistant configuration not yet implemented for IEEE 802.1x")
		// For now, fall back to manual certificate configuration
	}

	// Use common certificate configuration function
	handles, err := certs.ConfigureIEEE8021xCertificates(cmd.WSMan, cmd.IEEE8021xPrivateKey, cmd.IEEE8021xClientCert, cmd.IEEE8021xCACert)
	if err != nil {
		return fmt.Errorf("failed to configure certificates: %w", err)
	}

	// Get current IEEE 802.1x settings
	getIEEESettings, err := cmd.WSMan.GetIPSIEEE8021xSettings()
	if err != nil {
		return fmt.Errorf("failed to get current IEEE 802.1x settings: %w", err)
	}

	// Configure IEEE 802.1x settings using current settings as base
	request := ieee8021x.IEEE8021xSettingsRequest{
		ElementName:                     getIEEESettings.Body.IEEE8021xSettingsResponse.ElementName,
		InstanceID:                      getIEEESettings.Body.IEEE8021xSettingsResponse.InstanceID,
		Username:                        cmd.IEEE8021xUsername,
		AuthenticationProtocol:          cmd.IEEE8021xAuthenticationProtocol,
		AvailableInS0:                   true,
		Enabled:                         2, // Enabled
		PxeTimeout:                      120,
		RoamingIdentity:                 "",
		ServerCertificateName:           "",
		ServerCertificateNameComparison: 0,
	}

	// Only set password for PEAP-MSCHAPv2 (AuthenticationProtocol == 2)
	if request.AuthenticationProtocol == 2 {
		request.Password = cmd.IEEE8021xPassword
	}

	_, err = cmd.WSMan.PutIPSIEEE8021xSettings(request)
	if err != nil {
		return fmt.Errorf("failed to configure IEEE 802.1x settings: %w", err)
	}

	log.Info("IEEE8021x settings updated successfully")

	// Set certificates only for EAP-TLS (AuthenticationProtocol == 0)
	if cmd.IEEE8021xAuthenticationProtocol == 0 && (handles.RootCertHandle != "" || handles.ClientCertHandle != "") {
		_, err = cmd.WSMan.SetIPSIEEE8021xCertificates(handles.RootCertHandle, handles.ClientCertHandle)
		if err != nil {
			return fmt.Errorf("failed to set IEEE 802.1x certificates: %w", err)
		}
	}

	log.Infof("Successfully configured 802.1x profile: %s", cmd.IEEE8021xProfileName)

	return nil
}
