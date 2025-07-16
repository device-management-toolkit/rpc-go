/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type ConfigTLSInfo struct {
	TLSMode        int // Changed to int to avoid circular dependency
	DelayInSeconds int
	EAAddress      string
	EAUsername     string
	EAPassword     string
}

// authenticationMethodMap now maps strings directly to integer values
var authenticationMethod = map[string]wifi.AuthenticationMethod{
	"Other":         wifi.AuthenticationMethodOther,
	"OpenSystem":    wifi.AuthenticationMethodOpenSystem,
	"SharedKey":     wifi.AuthenticationMethodSharedKey,
	"WPAPSK":        wifi.AuthenticationMethodWPAPSK,
	"WPAIEEE8021x":  wifi.AuthenticationMethodWPAIEEE8021x,
	"WPA2PSK":       wifi.AuthenticationMethodWPA2PSK,
	"WPA2IEEE8021x": wifi.AuthenticationMethodWPA2IEEE8021x,
	"WPA3SAE":       wifi.AuthenticationMethodWPA3SAE,
	"WPA3OWE":       wifi.AuthenticationMethodWPA3OWE,
}

// encryptionMethod Map now maps strings directly to integer values
var encryptionMethod = map[string]wifi.EncryptionMethod{
	"Other": wifi.EncryptionMethod_Other,
	"WEP":   wifi.EncryptionMethod_WEP,
	"TKIP":  wifi.EncryptionMethod_TKIP,
	"CCMP":  wifi.EncryptionMethod_CCMP,
	"None":  wifi.EncryptionMethod_None,
}

func (f *Flags) printConfigurationUsage() {
	var sb strings.Builder

	baseCommand := fmt.Sprintf("%s %s", filepath.Base(os.Args[0]), utils.CommandConfigure)

	sb.WriteString(utils.HelpHeader)
	sb.WriteString("Usage: " + baseCommand + " COMMAND [OPTIONS]\n\n")
	sb.WriteString("Supported Configuration Commands:\n\n")

	commands := []struct {
		command string
		desc    string
		example string
	}{
		{utils.SubCommandWired, "Add or modify ethernet settings in AMT. Requires AMT password. A config file or command-line flags must be provided. No cloud interaction.", baseCommand + " " + utils.SubCommandWired + " -password YourAMTPassword -config ethernetconfig.yaml"},
		{utils.SubCommandWireless, "Add or modify WiFi settings in AMT. Requires AMT password. A config file or command-line flags must be provided. No cloud interaction.", baseCommand + " " + utils.SubCommandWireless + " -password YourAMTPassword -config wificonfig.yaml"},
		{utils.SubCommandEnableWifiPort, "Enable WiFi port and local profile synchronization in AMT. Requires AMT password.", baseCommand + " " + utils.SubCommandEnableWifiPort + " -password YourAMTPassword"},
		{utils.SubCommandSetMEBx, "Configure MEBx Password. Requires AMT password.", baseCommand + " " + utils.SubCommandSetMEBx + " -mebxpassword YourMEBxPassword -password YourAMTPassword"},
		{utils.SubCommandSyncClock, "Sync the host OS clock to AMT. Requires AMT password.", baseCommand + " " + utils.SubCommandSyncClock + " -password YourAMTPassword"},
		{utils.SubCommandSetAMTFeatures, "Enable/Disable KVM, SOL, IDER. Set user consent option (kvm, all, or none).", baseCommand + " " + utils.SubCommandSetAMTFeatures + " -userConsent all -kvm -sol -ider"},
		{utils.SubCommandChangeAMTPassword, "Update AMT password. If flags are omitted, passwords will be prompted. Requires AMT password.", baseCommand + " " + utils.SubCommandChangeAMTPassword + " -password YourAMTPassword -newamtpassword YourNewPassword"},
		{utils.SubCommandCIRA, "(Experimental) Configure CIRA. Enable CIRA. Requires AMT password.", baseCommand + " " + utils.SubCommandCIRA + " -mpspassword YourMPSPassword -mpsaddress myfqdn.com -mpscert <mpscert>"},
	}

	for _, cmd := range commands {
		sb.WriteString(fmt.Sprintf("  %-17s %s\n", cmd.command, cmd.desc))
		sb.WriteString(fmt.Sprintf("                    Example: %s\n", cmd.example))
	}

	sb.WriteString("\nRun '" + baseCommand + " COMMAND -h' for more information on a command.\n")

	usage := sb.String()
	fmt.Println(usage)
}

func (f *Flags) getAuthenticationCode(s string) (int, error) {
	for methodType, code := range authenticationMethod {
		if strings.EqualFold(s, methodType) {
			return int(code), nil
		}
	}

	return 0, utils.MissingOrInvalidConfiguration
}

func (f *Flags) getEncrytionCode(s string) (int, error) {
	for methodType, code := range encryptionMethod {
		if strings.EqualFold(s, methodType) {
			return int(code), nil
		}
	}

	return 0, utils.MissingOrInvalidConfiguration
}

func (f *Flags) mergeWifiSecrets(wifiSecretConfig config.SecretConfig) {
	for _, secret := range wifiSecretConfig.Secrets {
		if secret.ProfileName == "" {
			continue
		}

		if secret.PskPassphrase != "" {
			for i := range f.LocalConfig.WifiConfigs {
				item := &f.LocalConfig.WifiConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.PskPassphrase = secret.PskPassphrase
				}
			}
		}

		if secret.Password != "" {
			for i := range f.LocalConfig.Ieee8021xConfigs {
				item := &f.LocalConfig.Ieee8021xConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.Password = secret.Password
				}
			}
		}

		if secret.PrivateKey != "" {
			for i := range f.LocalConfig.Ieee8021xConfigs {
				item := &f.LocalConfig.Ieee8021xConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.PrivateKey = secret.PrivateKey
				}
			}
		}
	}
}

func (f *Flags) promptForSecrets() error {
	for i := range f.LocalConfig.WifiConfigs {
		item := &f.LocalConfig.WifiConfigs[i]
		if item.ProfileName == "" {
			continue
		}

		authMethod := wifi.AuthenticationMethod(item.AuthenticationMethod)
		if (authMethod == wifi.AuthenticationMethodWPAPSK || authMethod == wifi.AuthenticationMethodWPA2PSK) &&
			item.PskPassphrase == "" {
			err := f.PromptUserInput("Please enter PskPassphrase for "+item.ProfileName+": ", &item.PskPassphrase)
			if err != nil {
				return err
			}
		}
	}
	// If EA settings are provided without password, prompt for EA password
	if f.LocalConfig.EnterpriseAssistant.EAAddress != "" && f.LocalConfig.EnterpriseAssistant.EAUsername != "" {
		if f.LocalConfig.EnterpriseAssistant.EAPassword == "" {
			err := f.PromptUserInput("Please enter EA password: ", &f.LocalConfig.EnterpriseAssistant.EAPassword)
			if err != nil {
				return err
			}
		}

		f.LocalConfig.EnterpriseAssistant.EAConfigured = true

		return nil
	}
	// If EA settings are not provided, look for secrets in the secrets/config file
	for i := range f.LocalConfig.Ieee8021xConfigs {
		item := &f.LocalConfig.Ieee8021xConfigs[i]
		if item.ProfileName == "" {
			continue
		}

		if item.AuthenticationProtocol == ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2 && item.Password == "" {
			err := f.PromptUserInput("Please enter password for "+item.ProfileName+": ", &item.Password)
			if err != nil {
				return err
			}
		}

		if item.AuthenticationProtocol == ieee8021x.AuthenticationProtocolEAPTLS && item.PrivateKey == "" {
			err := f.PromptUserInput("Please enter private key for "+item.ProfileName+": ", &item.PrivateKey)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *Flags) verifyWifiConfigurations() error {
	priorities := make(map[int]bool)

	for _, cfg := range f.LocalConfig.WifiConfigs {
		//Check profile name is not empty
		if cfg.ProfileName == "" {
			log.Error("missing profile name")

			return utils.MissingOrInvalidConfiguration
		}
		//Check ssid is not empty
		if cfg.SSID == "" {
			log.Error("missing ssid for config: ", cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		}
		//Check priority is not empty
		if cfg.Priority <= 0 {
			log.Error("invalid priority for config: ", cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		}
		//Check priority is unique
		if priorities[cfg.Priority] {
			log.Error("priority was specified previously: ", cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		}

		priorities[cfg.Priority] = true

		authenticationMethod := wifi.AuthenticationMethod(cfg.AuthenticationMethod)
		switch authenticationMethod {
		case wifi.AuthenticationMethodWPAPSK:
			fallthrough
		case wifi.AuthenticationMethodWPA2PSK: // AuthenticationMethod 4
			if cfg.PskPassphrase == "" {
				log.Error("missing PskPassphrase for config: ", cfg.ProfileName)

				return utils.MissingOrInvalidConfiguration
			}
		case wifi.AuthenticationMethodWPAIEEE8021x:
			fallthrough
		case wifi.AuthenticationMethodWPA2IEEE8021x: // AuthenticationMethod 7
			if cfg.ProfileName == "" {
				log.Error("missing ieee8021x profile name")

				return utils.MissingOrInvalidConfiguration
			}

			if cfg.PskPassphrase != "" {
				log.Errorf("wifi configuration for 8021x contains passphrase: %s", cfg.ProfileName)

				return utils.MissingOrInvalidConfiguration
			}

			err := f.verifyMatchingIeee8021xConfig(cfg.Ieee8021xProfileName)
			if err != nil {
				return err
			}
		case wifi.AuthenticationMethodOther:
			log.Errorf("unsupported AuthenticationMethod_Other (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethodOpenSystem:
			log.Errorf("unsupported AuthenticationMethod_OpenSystem (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethodSharedKey:
			log.Errorf("unsupported AuthenticationMethod_SharedKey (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethodWPA3SAE:
			log.Errorf("unsupported AuthenticationMethod_WPA3_SAE (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethodWPA3OWE:
			log.Errorf("unsupported AuthenticationMethod_WPA3_OWE (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		default:
			log.Errorf("invalid AuthenticationMethod_VendorReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		}

		encryptionMethod := wifi.EncryptionMethod(cfg.EncryptionMethod)
		// NOTE: this is only
		switch encryptionMethod {
		case wifi.EncryptionMethod_TKIP:
			fallthrough
		case wifi.EncryptionMethod_CCMP: // EncryptionMethod 4
			break
		case wifi.EncryptionMethod_Other:
			log.Errorf("unsupported EncryptionMethod_Other (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		case wifi.EncryptionMethod_WEP:
			log.Errorf("unsupported EncryptionMethod_WEP (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		case wifi.EncryptionMethod_None:
			log.Errorf("unsupported EncryptionMethod_None (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		default:
			log.Errorf("invalid EncryptionMethod (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		}
	}

	return nil
}

func (f *Flags) verifyMatchingIeee8021xConfig(profileName string) error {
	foundOne := false

	for _, ieee802xCfg := range f.LocalConfig.Ieee8021xConfigs {
		if profileName != ieee802xCfg.ProfileName {
			continue
		}

		if foundOne {
			log.Error("duplicate IEEE8021x Profile names: ", ieee802xCfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		}

		foundOne = true

		err := f.verifyIeee8021xConfig(ieee802xCfg)
		if err != nil {
			return utils.MissingOrInvalidConfiguration
		}
	}

	if !foundOne {
		log.Error("missing IEEE8021x Profile: ", profileName)

		return utils.MissingOrInvalidConfiguration
	}

	return nil
}

func (f *Flags) verifyIeee8021xConfig(cfg config.Ieee8021xConfig) error {
	var err error = utils.MissingOrInvalidConfiguration

	isEAConfigured := f.LocalConfig.EnterpriseAssistant.EAConfigured
	if !isEAConfigured {
		if cfg.Username == "" {
			log.Error("missing username for config: ", cfg.ProfileName)

			return err
		}

		if cfg.CACert == "" {
			log.Error("missing caCert for config: ", cfg.ProfileName)

			return err
		}
	}
	// not all defined protocols are supported
	switch cfg.AuthenticationProtocol {
	case ieee8021x.AuthenticationProtocolEAPTLS:
		if !isEAConfigured {
			if cfg.ClientCert == "" {
				log.Error("missing clientCert for config: ", cfg.ProfileName)

				return err
			}

			if cfg.PrivateKey == "" {
				log.Error("missing privateKey for config: ", cfg.ProfileName)

				return err
			}
		}
	case ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2:
		if !isEAConfigured && cfg.Password == "" {
			log.Error("missing password for for PEAPv0_EAPMSCHAPv2 config: ", cfg.ProfileName)

			return err
		}
	case ieee8021x.AuthenticationProtocolEAPTTLS_MSCHAPv2:
		log.Errorf("unsupported AuthenticationProtocolEAPTTLS_MSCHAPv2 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	case ieee8021x.AuthenticationProtocolPEAPv1_EAPGTC:
		log.Errorf("unsupported AuthenticationProtocolPEAPv1_EAPGTC (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	case ieee8021x.AuthenticationProtocolEAPFAST_MSCHAPv2:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_MSCHAPv2 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	case ieee8021x.AuthenticationProtocolEAPFAST_GTC:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_GTC (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	case ieee8021x.AuthenticationProtocolEAP_MD5:
		log.Errorf("unsupported AuthenticationProtocolEAP_MD5 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	case ieee8021x.AuthenticationProtocolEAP_PSK:
		log.Errorf("unsupported AuthenticationProtocolEAP_PSK (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	case ieee8021x.AuthenticationProtocolEAP_SIM:
		log.Errorf("unsupported AuthenticationProtocolEAP_SIM (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	case ieee8021x.AuthenticationProtocolEAP_AKA:
		log.Errorf("unsupported AuthenticationProtocolEAP_AKA (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	case ieee8021x.AuthenticationProtocolEAPFAST_TLS:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_TLS (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	default:
		log.Errorf("invalid AuthenticationProtocol (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)

		return err
	}

	return nil
}
