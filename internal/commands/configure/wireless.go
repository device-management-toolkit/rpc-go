/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"
	"regexp"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// WirelessCmd represents WiFi configuration
type WirelessCmd struct {
	ConfigureBaseCmd

	// WiFi configuration
	ProfileName          string `help:"WiFi profile name" name:"profileName"`
	SSID                 string `help:"WiFi SSID" name:"ssid"`
	Priority             int    `help:"WiFi priority" name:"priority" default:"1"`
	AuthenticationMethod int    `help:"Authentication method (4=WPA-PSK, 6=WPA2-PSK, 7=WPA2-IEEE8021x)" enum:"4,6,7" default:"6" name:"authenticationMethod"`
	EncryptionMethod     int    `help:"Encryption method (3=TKIP, 4=CCMP)" enum:"3,4" default:"4" name:"encryptionMethod"`
	PSKPassphrase        string `help:"WPA/WPA2 passphrase" name:"pskPassphrase"`
}

// Validate implements Kong's Validate interface for wireless command validation
func (cmd *WirelessCmd) Validate() error {
	// First call the base Validate to handle password validation
	if err := cmd.ConfigureBaseCmd.Validate(); err != nil {
		return err
	}

	// Basic validation
	if cmd.ProfileName == "" {
		return fmt.Errorf("profile name is required")
	}

	if cmd.SSID == "" {
		return fmt.Errorf("SSID is required")
	}

	if cmd.Priority <= 0 {
		return fmt.Errorf("priority must be greater than 0")
	}

	// Profile names can only be alphanumeric (not even dashes)
	reAlphaNum := regexp.MustCompile("[^a-zA-Z0-9]+")
	if reAlphaNum.MatchString(cmd.ProfileName) {
		return fmt.Errorf("invalid wifi profile name: %s (only alphanumeric allowed)", cmd.ProfileName)
	}

	// Validate authentication method
	authMethod := wifi.AuthenticationMethod(cmd.AuthenticationMethod)
	switch authMethod {
	case wifi.AuthenticationMethodWPAPSK:
		fallthrough
	case wifi.AuthenticationMethodWPA2PSK:
		if cmd.PSKPassphrase == "" {
			return fmt.Errorf("PSK passphrase is required for WPA/WPA2-PSK authentication")
		}

		if cmd.IEEE8021xProfileName != "" {
			return fmt.Errorf("IEEE 802.1x profile name should not be specified for PSK authentication")
		}
	case wifi.AuthenticationMethodWPAIEEE8021x:
		fallthrough
	case wifi.AuthenticationMethodWPA2IEEE8021x:
		if cmd.PSKPassphrase != "" {
			return fmt.Errorf("PSK passphrase should not be specified for IEEE 802.1x authentication")
		}

		if cmd.IEEE8021xProfileName == "" {
			return fmt.Errorf("IEEE 802.1x profile name is required for IEEE 802.1x authentication")
		}
	case wifi.AuthenticationMethodOther:
		return fmt.Errorf("unsupported authentication method: Other (%d)", cmd.AuthenticationMethod)
	case wifi.AuthenticationMethodOpenSystem:
		return fmt.Errorf("unsupported authentication method: OpenSystem (%d)", cmd.AuthenticationMethod)
	case wifi.AuthenticationMethodSharedKey:
		return fmt.Errorf("unsupported authentication method: SharedKey (%d)", cmd.AuthenticationMethod)
	case wifi.AuthenticationMethodWPA3SAE:
		return fmt.Errorf("unsupported authentication method: WPA3_SAE (%d)", cmd.AuthenticationMethod)
	case wifi.AuthenticationMethodWPA3OWE:
		return fmt.Errorf("unsupported authentication method: WPA3_OWE (%d)", cmd.AuthenticationMethod)
	default:
		return fmt.Errorf("invalid authentication method: %d", cmd.AuthenticationMethod)
	}

	// Validate encryption method
	encMethod := wifi.EncryptionMethod(cmd.EncryptionMethod)
	switch encMethod {
	case wifi.EncryptionMethodTKIP:
		fallthrough
	case wifi.EncryptionMethodCCMP:
		// Valid encryption methods
		break
	case wifi.EncryptionMethodOther:
		return fmt.Errorf("unsupported encryption method: Other (%d)", cmd.EncryptionMethod)
	case wifi.EncryptionMethodWEP:
		return fmt.Errorf("unsupported encryption method: WEP (%d)", cmd.EncryptionMethod)
	case wifi.EncryptionMethodNone:
		return fmt.Errorf("unsupported encryption method: None (%d)", cmd.EncryptionMethod)
	default:
		return fmt.Errorf("invalid encryption method: %d", cmd.EncryptionMethod)
	}

	return nil
}

// Run executes the wireless configuration command
func (cmd *WirelessCmd) Run(ctx *commands.Context) error {
	log.Infof("configuring wifi profile: %s", cmd.ProfileName)

	// Set wifiEndpointSettings properties from command parameters
	wifiEndpointSettings := wifi.WiFiEndpointSettingsRequest{
		ElementName:          cmd.ProfileName,
		InstanceID:           fmt.Sprintf("Intel(r) AMT:WiFi Endpoint Settings %s", cmd.ProfileName),
		SSID:                 cmd.SSID,
		Priority:             cmd.Priority,
		AuthenticationMethod: wifi.AuthenticationMethod(cmd.AuthenticationMethod),
		EncryptionMethod:     wifi.EncryptionMethod(cmd.EncryptionMethod),
	}

	cmd.ClearWirelessProfiles()

	// If no 802.1x profile is specified, use PSK passphrase
	var (
		ieee8021xSettings models.IEEE8021xSettings
		handles           *certs.IEEE8021xCertHandles
	)

	if cmd.IEEE8021xProfileName == "" {
		wifiEndpointSettings.PSKPassPhrase = cmd.PSKPassphrase
		handles = &certs.IEEE8021xCertHandles{}
	} else {
		// Implement 802.1x configuration
		var err error

		ieee8021xSettings, handles, err = cmd.setIeee8021xConfig()
		if err != nil {
			return fmt.Errorf("failed to configure IEEE 802.1x settings: %w", err)
		}
	}
	// pause to allow amt to handle certs
	utils.Pause(1)

	// Add WiFi settings via WSMAN
	_, err := cmd.WSMan.AddWiFiSettings(wifiEndpointSettings, ieee8021xSettings, "WiFi Endpoint 0", handles.ClientCertHandle, handles.RootCertHandle)
	if err != nil {
		log.Errorf("failed configuring: %s", cmd.ProfileName)

		return fmt.Errorf("failed to configure WiFi settings: %w", err)
	}

	log.Infof("successfully configured: %s", cmd.ProfileName)

	return nil
}

// setIeee8021xConfig configures IEEE 802.1x settings for WiFi
func (cmd *WirelessCmd) setIeee8021xConfig() (ieee8021xSettings models.IEEE8021xSettings, handles *certs.IEEE8021xCertHandles, err error) {
	// Use common certificate configuration function
	handles, err = certs.ConfigureIEEE8021xCertificates(cmd.WSMan, cmd.IEEE8021xPrivateKey, cmd.IEEE8021xClientCert, cmd.IEEE8021xCACert)
	if err != nil {
		return ieee8021xSettings, nil, fmt.Errorf("failed to configure certificates: %w", err)
	}

	// Set basic IEEE 802.1x settings
	ieee8021xSettings = models.IEEE8021xSettings{
		ElementName:            cmd.IEEE8021xProfileName,
		InstanceID:             fmt.Sprintf("Intel(r) AMT: 8021X Settings %s", cmd.IEEE8021xProfileName),
		AuthenticationProtocol: models.AuthenticationProtocol(cmd.IEEE8021xAuthenticationProtocol),
		Username:               cmd.IEEE8021xUsername,
	}

	// For PEAP-MSCHAPv2, set password
	if ieee8021xSettings.AuthenticationProtocol == models.AuthenticationProtocol(ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2) {
		ieee8021xSettings.Password = cmd.IEEE8021xPassword
	}

	return ieee8021xSettings, handles, nil
}

func (cmd *WirelessCmd) ClearWirelessProfiles() error {
	// Get WiFi Profiles
	wifiEndpointSettings, err := cmd.WSMan.GetWiFiSettings()
	if err != nil {
		return err
	}

	// Delete the existing WiFi profiles
	for _, wifiSetting := range wifiEndpointSettings {
		// Skip wifiSettings with no InstanceID
		if wifiSetting.InstanceID == "" {
			continue
		}

		log.Infof("deleting wifiSetting: %s", wifiSetting.InstanceID)

		err := cmd.WSMan.DeleteWiFiSetting(wifiSetting.InstanceID)
		if err != nil {
			log.Infof("unable to delete: %s %s", wifiSetting.InstanceID, err)

			continue
		}

		log.Infof("successfully deleted wifiSetting: %s", wifiSetting.InstanceID)
	}

	// Delete unused certificates
	err = certs.PruneCerts(cmd.WSMan)
	if err != nil {
		return utils.WiFiConfigurationFailed
	}

	return nil
}
