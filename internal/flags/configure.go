/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/config"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type TLSMode int

const (
	TLSModeServer TLSMode = iota
	TLSModeServerAndNonTLS
	TLSModeMutual
	TLSModeMutualAndNonTLS
	TLSModeDisabled
)

func (m TLSMode) String() string {
	switch m {
	case TLSModeServer:
		return "Server"
	case TLSModeServerAndNonTLS:
		return "ServerAndNonTLS"
	case TLSModeMutual:
		return "Mutual"
	case TLSModeMutualAndNonTLS:
		return "MutualAndNonTLS"
	case TLSModeDisabled:
		return "None"
	default:
		return "Unknown"
	}
}

func TLSModesToString() string {
	return fmt.Sprintf("%s, %s, %s, %s, %s", TLSModeServer, TLSModeServerAndNonTLS, TLSModeMutual, TLSModeMutualAndNonTLS, TLSModeDisabled)
}

func ParseTLSMode(s string) (TLSMode, error) {
	var m TLSMode

	var err error

	switch s {
	case "Server":
		m = TLSModeServer
	case "ServerAndNonTLS":
		m = TLSModeServerAndNonTLS
	case "Mutual":
		m = TLSModeMutual
	case "MutualAndNonTLS":
		m = TLSModeMutualAndNonTLS
	case "None":
		m = TLSModeDisabled
	default:
		// flags error handling already shows appropriate message
		err = errors.New("")
	}

	return m, err
}

type ConfigTLSInfo struct {
	TLSMode        TLSMode
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
	baseCommand := fmt.Sprintf("%s %s", filepath.Base(os.Args[0]), utils.CommandConfigure)
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"
	usage += "Usage: " + baseCommand + " COMMAND [OPTIONS]\n\n"
	usage += "Supported Configuration Commands:\n"
	usage += "  " + utils.SubCommandWired + " Add or modify ethernet settings in AMT. AMT password is required. A config.yml or command line flags must be provided for all settings. This command runs without cloud interaction.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandWired + " -password YourAMTPassword -config ethernetconfig.yaml\n"
	usage += "  " + utils.SubCommandWireless + " Add or modify WiFi settings in AMT. AMT password is required. A config.yml or command line flags must be provided for all settings. This command runs without cloud interaction.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandWireless + " -password YourAMTPassword -config wificonfig.yaml\n"
	usage += "  " + utils.SubCommandEnableWifiPort + "  Enables WiFi port and local profile synchronization settings in AMT. AMT password is required.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandEnableWifiPort + " -password YourAMTPassword\n"
	usage += "  " + utils.SubCommandConfigureTLS + "             Configures TLS in AMT. AMT password is required.  A config.yml or command line flags must be provided for all settings. This command runs without cloud interaction.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandConfigureTLS + " -mode Server -password YourAMTPassword\n"
	usage += "  " + utils.SubCommandSetMEBx + "            Configures MEBx Password. AMT password is required.\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandSetMEBx + " -mebxpassword YourMEBxPassword -password YourAMTPassword\n"
	usage += "  " + utils.SubCommandSyncClock + "       Sync the host OS clock to AMT. AMT password is required\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandSyncClock + " -password YourAMTPassword\n"
	usage += "  " + utils.SubCommandSetAMTFeatures + "     Enables or Disables KVM, SOL, IDER. Sets user consent option (kvm, all, or none).\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandSetAMTFeatures + " -userConsent all -kvm -sol -ider\n"
	usage += "  " + utils.SubCommandChangeAMTPassword + "     Updates AMT password. If flags are not provided, new and current AMT passwords will be prompted for. AMT password is required\n"
	usage += "                  Example: " + baseCommand + " " + utils.SubCommandChangeAMTPassword + " -password YourAMTPassword -newamtpassword YourNewPassword\n"
	usage += "\nRun '" + baseCommand + " COMMAND -h' for more information on a command.\n"
	fmt.Println(usage)
}

func (f *Flags) handleConfigureCommand() error {
	if len(f.commandLineArgs) == 2 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	var err error

	f.SubCommand = f.commandLineArgs[2]
	switch f.SubCommand {
	case utils.SubCommandAddEthernetSettings:
		log.Info("Sub command \"wiredsettings\" is deprecated use \"wired\" instead")

		err = f.handleAddEthernetSettings()
	case utils.SubCommandWired:
		err = f.handleAddEthernetSettings()
	case utils.SubCommandAddWifiSettings:
		log.Info("Sub command \"addwifisettings\" is deprecated use \"wireless\" instead")

		err = f.handleAddWifiSettings()
	case utils.SubCommandWireless:
		err = f.handleAddWifiSettings()
	case utils.SubCommandEnableWifiPort:
		err = f.handleEnableWifiPort()
	case utils.SubCommandConfigureTLS:
		err = f.handleConfigureTLS()
	case utils.SubCommandSetMEBx:
		err = f.handleMEBxPassword()
	case utils.SubCommandSyncClock:
		err = f.handleSyncClock()
	case utils.SubCommandChangeAMTPassword:
		err = f.handleChangeAMTPassword()
	case utils.SubCommandSetAMTFeatures:
		err = f.handleSetAMTFeatures()
	default:
		f.printConfigurationUsage()

		err = utils.IncorrectCommandLineParameters
	}

	if err != nil {
		return err
	}

	f.Local = true
	if f.SubCommand != utils.SubCommandSetAMTFeatures {
		if f.Password == "" {
			if f.LocalConfig.Password != "" {
				f.Password = f.LocalConfig.Password
			} else {
				if err = f.ReadPasswordFromUser(); err != nil {
					return utils.MissingOrIncorrectPassword
				}

				f.LocalConfig.Password = f.Password
			}
		} else {
			if f.LocalConfig.Password == "" {
				f.LocalConfig.Password = f.Password
			} else if f.LocalConfig.Password != f.Password {
				log.Error("password does not match config file password")
				return utils.MissingOrIncorrectPassword
			}
		}
	}

	return nil
}

func (f *Flags) handleChangeAMTPassword() error {
	fs := f.NewConfigureFlagSet(utils.SubCommandChangeAMTPassword)
	fs.StringVar(&f.NewPassword, "newamtpassword", "", "New AMT password")

	if len(f.commandLineArgs) > 3 {
		if err := fs.Parse(f.commandLineArgs[3:]); err != nil {
			f.printConfigurationUsage()
			return utils.IncorrectCommandLineParameters
		}
	}

	if f.Password == "" {
		if rc := f.ReadPasswordFromUser(); rc != nil {
			return rc
		}
	}

	if f.NewPassword == "" {
		if rc := f.ReadNewPasswordTo(&f.NewPassword, "New AMT Password"); rc != nil {
			return rc
		}
	}

	return nil
}

func (f *Flags) handleSyncClock() error {
	if err := f.amtMaintenanceSyncClockCommand.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	return nil
}

func (f *Flags) handleSetAMTFeatures() error {
	var err error

	if len(f.commandLineArgs) == 3 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	f.flagSetAMTFeatures.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetAMTFeatures.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetAMTFeatures.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetAMTFeatures.StringVar(&f.UserConsent, "userConsent", "", "Sets userconsent (ACM only): kvm, all, none")
	f.flagSetAMTFeatures.BoolVar(&f.KVM, "kvm", false, "Enables or Disables KVM (Keyboard, Video, Mouse)")
	f.flagSetAMTFeatures.BoolVar(&f.SOL, "sol", false, "Enables or Disables SOL (Serial Over LAN)")
	f.flagSetAMTFeatures.BoolVar(&f.IDER, "ider", false, "Enables or Disables IDER (IDE Redirection)")
	f.flagSetAMTFeatures.StringVar(&f.Password, "password", utils.LookupEnv("AMT_PASSWORD"), "AMT password")

	// V2 features
	f.flagSetAMTFeatures.StringVar(&f.configContentV2, "configv2", "", "specify a config file or smb: file share URL")
	f.flagSetAMTFeatures.StringVar(&f.configV2Key, "configencryptionkey", utils.LookupEnv("CONFIG_ENCRYPTION_KEY"), "provide the 32 byte key to decrypt the config file")

	if err = f.flagSetAMTFeatures.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	if f.configContentV2 != "" {
		err := f.handleLocalConfigV2()
		if err != nil {
			return utils.FailedReadingConfiguration
		}

		// Set the values from the v2 config file.
		if f.LocalConfigV2.Configuration.Redirection.UserConsent != "" {
			f.UserConsent = f.LocalConfigV2.Configuration.Redirection.UserConsent
		}

		f.KVM = f.LocalConfigV2.Configuration.Redirection.Services.KVM
		f.SOL = f.LocalConfigV2.Configuration.Redirection.Services.SOL
		f.IDER = f.LocalConfigV2.Configuration.Redirection.Services.IDER
		f.Password = f.LocalConfigV2.Configuration.AMTSpecific.AdminPassword
	}

	// Validate UserConsent
	if f.UserConsent != "" {
		f.UserConsent = strings.ToLower(f.UserConsent)
		switch f.UserConsent {
		case "kvm", "all", "none":
			return nil
		default:
			f.printConfigurationUsage()
			log.Error("invalid value for userconsent: ", f.UserConsent)

			return utils.IncorrectCommandLineParameters
		}
	}

	return nil
}

func (f *Flags) handleMEBxPassword() error {
	f.flagSetMEBx.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetMEBx.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetMEBx.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetMEBx.StringVar(&f.Password, "password", utils.LookupEnv("AMT_PASSWORD"), "AMT password")
	f.flagSetMEBx.StringVar(&f.MEBxPassword, "mebxpassword", utils.LookupEnv("MEBX_PASSWORD"), "MEBX password")
	// V2 features
	f.flagSetMEBx.StringVar(&f.configContentV2, "configv2", "", "specify a config file or smb: file share URL")
	f.flagSetMEBx.StringVar(&f.configV2Key, "configencryptionkey", utils.LookupEnv("CONFIG_ENCRYPTION_KEY"), "provide the 32 byte key to decrypt the config file")

	if len(f.commandLineArgs) > 3 {
		if err := f.flagSetMEBx.Parse(f.commandLineArgs[3:]); err != nil {
			f.printConfigurationUsage()
			return utils.IncorrectCommandLineParameters
		}
	}

	if f.configContentV2 != "" {
		err := f.handleLocalConfigV2()
		if err != nil {
			return utils.FailedReadingConfiguration
		}

		// Set the values from the v2 config file.
		f.MEBxPassword = f.LocalConfigV2.Configuration.AMTSpecific.MEBXPassword
		f.Password = f.LocalConfigV2.Configuration.AMTSpecific.AdminPassword
	}

	if f.Password == "" {
		if rc := f.ReadPasswordFromUser(); rc != nil {
			return rc
		}
	}

	if f.MEBxPassword == "" {
		if rc := f.ReadNewPasswordTo(&f.MEBxPassword, "New MEBx Password"); rc != nil {
			return rc
		}
	}

	return nil
}

func (f *Flags) handleEnableWifiPort() error {
	var err error
	// var rc error
	if len(f.commandLineArgs) > 5 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	f.flagSetEnableWifiPort.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetEnableWifiPort.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetEnableWifiPort.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetEnableWifiPort.StringVar(&f.Password, "password", utils.LookupEnv("AMT_PASSWORD"), "AMT password")

	if err = f.flagSetEnableWifiPort.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	return nil
}

func (f *Flags) NewConfigureFlagSet(subCommand string) *flag.FlagSet {
	fs := flag.NewFlagSet(subCommand, flag.ContinueOnError)
	// these flags are common to all configuration commands
	fs.BoolVar(&f.Verbose, "v", false, "Verbose output")
	fs.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	fs.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	fs.StringVar(&f.Password, "password", utils.LookupEnv("AMT_PASSWORD"), "AMT password")

	return fs
}

func (f *Flags) handleConfigureTLS() error {
	fs := f.NewConfigureFlagSet(utils.SubCommandConfigureTLS)
	tlsModeUsage := fmt.Sprintf("TLS authentication usage model (%s) (default %s)", TLSModesToString(), f.ConfigTLSInfo.TLSMode)
	fs.Func("mode", tlsModeUsage, func(flagValue string) error {
		var e error
		f.ConfigTLSInfo.TLSMode, e = ParseTLSMode(flagValue)

		return e
	})

	fs.StringVar(&f.configContent, "config", "", "specify a config file")
	fs.IntVar(&f.ConfigTLSInfo.DelayInSeconds, "delay", 3, "Delay time in seconds after putting remote TLS settings")
	fs.StringVar(&f.ConfigTLSInfo.EAAddress, "eaAddress", "", "Enterprise Assistant address")
	fs.StringVar(&f.ConfigTLSInfo.EAUsername, "eaUsername", "", "Enterprise Assistant username")
	fs.StringVar(&f.ConfigTLSInfo.EAPassword, "eaPassword", "", "Enterprise Assistant password")

	// V2 features
	fs.StringVar(&f.configContentV2, "configv2", "", "specify a config file or smb: file share URL")
	fs.StringVar(&f.configV2Key, "configencryptionkey", utils.LookupEnv("CONFIG_ENCRYPTION_KEY"), "provide the 32 byte key to decrypt the config file")

	if len(f.commandLineArgs) < (3 + 0) {
		fs.Usage()
		return utils.IncorrectCommandLineParameters
	}

	if err := fs.Parse(f.commandLineArgs[3:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}

	if len(fs.Args()) > 0 {
		fmt.Printf("unhandled additional args: %v\n", fs.Args())
		fs.Usage()

		return utils.IncorrectCommandLineParameters
	}

	if f.configContentV2 != "" {
		err := f.handleLocalConfigV2()
		if err != nil {
			return utils.FailedReadingConfiguration
		}

		f.LocalConfig.Password = f.LocalConfigV2.Configuration.AMTSpecific.AdminPassword
		mutualAuth := f.LocalConfigV2.Configuration.TLS.MutualAuthentication
		enabled := f.LocalConfigV2.Configuration.TLS.Enabled
		allowNonTLS := f.LocalConfigV2.Configuration.TLS.AllowNonTLS
		mode := f.DetermineTLSMode(mutualAuth, enabled, allowNonTLS)
		f.ConfigTLSInfo.TLSMode, _ = ParseTLSMode(mode)
		// ToDo: No need check whether it has to include in config file or default value to 3
		f.ConfigTLSInfo.DelayInSeconds = 3
		f.ConfigTLSInfo.EAAddress = f.LocalConfigV2.Configuration.EnterpriseAssistant.URL
		f.ConfigTLSInfo.EAUsername = f.LocalConfigV2.Configuration.EnterpriseAssistant.Username
		f.ConfigTLSInfo.EAPassword = f.LocalConfigV2.Configuration.EnterpriseAssistant.Password
	}

	if f.configContent != "" {
		err := f.handleLocalConfig()
		if err != nil {
			return utils.FailedReadingConfiguration
		}

		f.ConfigTLSInfo.TLSMode, _ = ParseTLSMode(f.LocalConfig.TlsConfig.Mode)
		f.ConfigTLSInfo.DelayInSeconds = f.LocalConfig.TlsConfig.Delay
		f.ConfigTLSInfo.EAAddress = f.LocalConfig.EnterpriseAssistant.EAAddress
		f.ConfigTLSInfo.EAUsername = f.LocalConfig.EnterpriseAssistant.EAUsername
		f.ConfigTLSInfo.EAPassword = f.LocalConfig.EnterpriseAssistant.EAPassword
	}

	if f.ConfigTLSInfo.EAAddress != "" && f.ConfigTLSInfo.EAUsername != "" {
		if f.ConfigTLSInfo.EAPassword == "" {
			err := f.PromptUserInput("Please enter EA password: ", &f.ConfigTLSInfo.EAPassword)
			if err != nil {
				return err
			}
		}

		f.LocalConfig.EnterpriseAssistant.EAConfigured = true
	}

	return nil
}

func (f *Flags) DetermineTLSMode(mutualAuth, enabled, allowNonTLS bool) string {
	switch {
	case enabled && !allowNonTLS && !mutualAuth:
		return "Server"
	case enabled && allowNonTLS && !mutualAuth:
		return "ServerAndNonTLS"
	case enabled && !allowNonTLS && mutualAuth:
		return "Mutual"
	case enabled && allowNonTLS && mutualAuth:
		return "MutualAndNonTLS"
	case !enabled:
		return "None"
	default:
		return "Unknown"
	}
}

func (f *Flags) handleAddEthernetSettings() error {
	var configJson string

	var secretsFilePath string

	var secretConfig config.SecretConfig

	// V2 features
	f.flagSetAddEthernetSettings.StringVar(&f.configContentV2, "configv2", "", "specify a config file or smb: file share URL")
	f.flagSetAddEthernetSettings.StringVar(&f.configV2Key, "configencryptionkey", utils.LookupEnv("CONFIG_ENCRYPTION_KEY"), "provide the 32 byte key to decrypt the config file")

	f.flagSetAddEthernetSettings.StringVar(&f.configContent, "config", "", "specify a config file or smb: file share URL")
	f.flagSetAddEthernetSettings.StringVar(&configJson, "configJson", "", "configuration as a JSON string")
	f.flagSetAddEthernetSettings.StringVar(&secretsFilePath, "secrets", "", "specify a secrets file ")

	wiredSettings := config.EthernetConfig{}
	f.flagSetAddEthernetSettings.BoolVar(&wiredSettings.DHCP, "dhcp", false, "Configures wired settings to use dhcp")
	f.flagSetAddEthernetSettings.BoolVar(&wiredSettings.Static, "static", false, "Configures wired settings to use static ip address")
	f.flagSetAddEthernetSettings.BoolVar(&wiredSettings.IpSync, "ipsync", false, "Sync the IP configuration of the host OS to AMT Network Settings")
	f.flagSetAddEthernetSettings.Func(
		"ipaddress",
		"IP address to be assigned to AMT",
		validateIP(&wiredSettings.IpAddress))
	f.flagSetAddEthernetSettings.Func(
		"subnetmask",
		"Subnetwork mask to be assigned to AMT",
		validateIP(&wiredSettings.Subnetmask))
	f.flagSetAddEthernetSettings.Func("gateway", "Gateway address to be assigned to AMT", validateIP(&wiredSettings.Gateway))
	f.flagSetAddEthernetSettings.Func("primarydns", "Primary DNS to be assigned to AMT", validateIP(&wiredSettings.PrimaryDNS))
	f.flagSetAddEthernetSettings.Func("secondarydns", "Secondary DNS to be assigned to AMT", validateIP(&wiredSettings.SecondaryDNS))
	f.flagSetAddEthernetSettings.StringVar(&wiredSettings.Ieee8021xProfileName, "ieee8021xProfileName", "", "specify 802.1x profile name")
	f.flagSetAddEthernetSettings.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetAddEthernetSettings.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetAddEthernetSettings.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetAddEthernetSettings.StringVar(&f.Password, "password", utils.LookupEnv("AMT_PASSWORD"), "AMT password")

	ieee8021xCfg := config.Ieee8021xConfig{}
	f.flagSetAddEthernetSettings.StringVar(&ieee8021xCfg.Username, "username", "", "specify username")
	f.flagSetAddEthernetSettings.StringVar(&ieee8021xCfg.Password, "ieee8021xPassword", utils.LookupEnv("IEE8021X_PASSWORD"), "8021x password if authenticationProtocol is PEAPv0/EAP-MSCHAPv2(2)")
	f.flagSetAddEthernetSettings.IntVar(&ieee8021xCfg.AuthenticationProtocol, "authenticationProtocol", 0, "specify authentication protocol")
	f.flagSetAddEthernetSettings.StringVar(&ieee8021xCfg.ClientCert, "clientCert", "", "specify client certificate")
	f.flagSetAddEthernetSettings.StringVar(&ieee8021xCfg.CACert, "caCert", "", "specify CA certificate")
	f.flagSetAddEthernetSettings.StringVar(&ieee8021xCfg.PrivateKey, "privateKey", utils.LookupEnv("IEE8021X_PRIVATE_KEY"), "specify private key")

	eaSettings := config.EnterpriseAssistant{}
	f.flagSetAddEthernetSettings.StringVar(&eaSettings.EAAddress, "eaAddress", "", "Enterprise Assistant address")
	f.flagSetAddEthernetSettings.StringVar(&eaSettings.EAUsername, "eaUsername", "", "Enterprise Assistant username")
	f.flagSetAddEthernetSettings.StringVar(&eaSettings.EAPassword, "eaPassword", "", "Enterprise Assistant password")

	if err := f.flagSetAddEthernetSettings.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	// update the config with the data read from flags
	f.LocalConfig.WiredConfig = wiredSettings
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfg)
	f.LocalConfig.EnterpriseAssistant = eaSettings

	if f.configContentV2 != "" && f.configV2Key != "" {
		err := f.handleLocalConfigV2()
		if err != nil {
			return utils.FailedReadingConfiguration
		}

		f.LocalConfig.Password = f.LocalConfigV2.Configuration.AMTSpecific.AdminPassword
		f.LocalConfig.WiredConfig.DHCP = f.LocalConfigV2.Configuration.Network.Wired.DHCPEnabled
		f.LocalConfig.WiredConfig.Static = f.LocalConfigV2.Configuration.Network.Wired.SharedStaticIP
		f.LocalConfig.WiredConfig.IpSync = f.LocalConfigV2.Configuration.Network.Wired.IPSyncEnabled
		f.LocalConfig.WiredConfig.IpAddress = f.LocalConfigV2.Configuration.Network.Wired.IPAddress
		f.LocalConfig.WiredConfig.Subnetmask = f.LocalConfigV2.Configuration.Network.Wired.SubnetMask
		f.LocalConfig.WiredConfig.Gateway = f.LocalConfigV2.Configuration.Network.Wired.DefaultGateway
		f.LocalConfig.WiredConfig.PrimaryDNS = f.LocalConfigV2.Configuration.Network.Wired.PrimaryDNS
		f.LocalConfig.WiredConfig.SecondaryDNS = f.LocalConfigV2.Configuration.Network.Wired.SecondaryDNS

		if f.LocalConfigV2.Configuration.Network.Wired.IEEE8021x != nil {
			f.LocalConfig.WiredConfig.Ieee8021xProfileName = "wiredIEEE8021x"
			f.LocalConfig.Ieee8021xConfigs[0].ProfileName = "wiredIEEE8021x"
			f.LocalConfig.Ieee8021xConfigs[0].Username = f.LocalConfigV2.Configuration.Network.Wired.IEEE8021x.Username
			f.LocalConfig.Ieee8021xConfigs[0].Password = f.LocalConfigV2.Configuration.Network.Wired.IEEE8021x.Password
			f.LocalConfig.Ieee8021xConfigs[0].AuthenticationProtocol = f.LocalConfigV2.Configuration.Network.Wired.IEEE8021x.AuthenticationProtocol
			f.LocalConfig.Ieee8021xConfigs[0].ClientCert = f.LocalConfigV2.Configuration.Network.Wired.IEEE8021x.ClientCert
			f.LocalConfig.Ieee8021xConfigs[0].CACert = f.LocalConfigV2.Configuration.Network.Wired.IEEE8021x.CACert
			f.LocalConfig.Ieee8021xConfigs[0].PrivateKey = f.LocalConfigV2.Configuration.Network.Wired.IEEE8021x.PrivateKey

			if !f.LocalConfig.EnterpriseAssistant.EAConfigured {
				f.LocalConfig.EnterpriseAssistant.EAAddress = f.LocalConfigV2.Configuration.EnterpriseAssistant.URL
				f.LocalConfig.EnterpriseAssistant.EAUsername = f.LocalConfigV2.Configuration.EnterpriseAssistant.Username
				f.LocalConfig.EnterpriseAssistant.EAPassword = f.LocalConfigV2.Configuration.EnterpriseAssistant.Password
				f.LocalConfig.EnterpriseAssistant.EAConfigured = true
			}
		}
	}

	if f.configContent != "" || configJson != "" {
		err := f.handleLocalConfig()
		if err != nil {
			return utils.FailedReadingConfiguration
		}

		if configJson != "" {
			err := json.Unmarshal([]byte(configJson), &f.LocalConfig)
			if err != nil {
				log.Error(err)
				return utils.IncorrectCommandLineParameters
			}
		}
	} else {
		// if no config file is provided, set IEEE profile name as given in WiredConfig
		if f.LocalConfig.WiredConfig.Ieee8021xProfileName != "" && len(f.LocalConfig.Ieee8021xConfigs) > 0 {
			f.LocalConfig.Ieee8021xConfigs[0].ProfileName = f.LocalConfig.WiredConfig.Ieee8021xProfileName
		}
	}

	if f.LocalConfig.WiredConfig.DHCP == f.LocalConfig.WiredConfig.Static {
		log.Error("must specify -dhcp or -static, but not both")
		return utils.InvalidParameterCombination
	}

	if f.LocalConfig.WiredConfig.DHCP && !f.LocalConfig.WiredConfig.IpSync {
		return utils.InvalidParameterCombination
	}

	if f.LocalConfig.WiredConfig.IpSync {
		if f.LocalConfig.WiredConfig.IpAddress != "" ||
			f.LocalConfig.WiredConfig.Subnetmask != "" ||
			f.LocalConfig.WiredConfig.Gateway != "" ||
			f.LocalConfig.WiredConfig.PrimaryDNS != "" ||
			f.LocalConfig.WiredConfig.SecondaryDNS != "" {
			return utils.InvalidParameterCombination
		}
	}

	if f.LocalConfig.WiredConfig.Static && !f.LocalConfig.WiredConfig.IpSync {
		if f.LocalConfig.WiredConfig.IpAddress == "" {
			return utils.MissingOrIncorrectStaticIP
		}

		if f.LocalConfig.WiredConfig.Subnetmask == "" {
			return utils.MissingOrIncorrectNetworkMask
		}

		if f.LocalConfig.WiredConfig.Gateway == "" {
			return utils.MissingOrIncorrectGateway
		}

		if f.LocalConfig.WiredConfig.PrimaryDNS == "" {
			return utils.MissingOrIncorrectPrimaryDNS
		}
	}

	if secretsFilePath != "" {
		err := cleanenv.ReadConfig(secretsFilePath, &secretConfig)
		if err != nil {
			log.Error("error reading secrets file: ", err)
			return utils.FailedReadingConfiguration
		}
	}

	err := f.verifyWiredIeee8021xConfig(secretConfig)
	if err != nil {
		return err
	}

	return nil
}

func (f *Flags) verifyWiredIeee8021xConfig(secretConfig config.SecretConfig) error {
	// Check if the 802.1x profile name is set
	if f.LocalConfig.WiredConfig.Ieee8021xProfileName == "" {
		return nil
	}
	// Check and prompt for EA password if necessary
	if f.LocalConfig.EnterpriseAssistant.EAAddress != "" && f.LocalConfig.EnterpriseAssistant.EAUsername != "" {
		if f.LocalConfig.EnterpriseAssistant.EAPassword == "" {
			if err := f.PromptUserInput("Please enter EA password: ", &f.LocalConfig.EnterpriseAssistant.EAPassword); err != nil {
				return err
			}
		}

		f.LocalConfig.EnterpriseAssistant.EAConfigured = true
	}
	// Find and validate the 802.1x config
	var wired8021xConfig *config.Ieee8021xConfig

	for i, item := range f.LocalConfig.Ieee8021xConfigs {
		if item.ProfileName == f.LocalConfig.WiredConfig.Ieee8021xProfileName {
			wired8021xConfig = &f.LocalConfig.Ieee8021xConfigs[i]
			break
		}
	}
	// If the profile was not found, log and return an error
	if wired8021xConfig == nil {
		log.Error("ieee8021x profile name does not match")
		return utils.MissingOrInvalidConfiguration
	}
	// Verify authentication protocol
	if wired8021xConfig.AuthenticationProtocol != ieee8021x.AuthenticationProtocolEAPTLS && wired8021xConfig.AuthenticationProtocol != ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2 {
		log.Error("invalid authentication protocol for wired 802.1x")
		return utils.MissingOrInvalidConfiguration
	}
	// Merge secrets with configs
	if !f.LocalConfig.EnterpriseAssistant.EAConfigured && secretConfig.Secrets != nil {
		for _, secret := range secretConfig.Secrets {
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
	// Prompt for private key if not already configured
	if !f.LocalConfig.EnterpriseAssistant.EAConfigured && wired8021xConfig.PrivateKey == "" {
		return f.PromptUserInput("Please enter private key for "+wired8021xConfig.ProfileName+": ", &wired8021xConfig.PrivateKey)
	}
	// Verify matching 802.1x config
	if err := f.verifyMatchingIeee8021xConfig(wired8021xConfig.ProfileName); err != nil {
		return err
	}

	return nil
}

func (f *Flags) handleAddWifiSettings() error {
	var err error

	var secretsFilePath string

	var wifiSecretConfig config.SecretConfig

	var configJson string

	// V2 features
	f.flagSetAddWifiSettings.StringVar(&f.configContentV2, "configv2", "", "specify a config file or smb: file share URL")
	f.flagSetAddWifiSettings.StringVar(&f.configV2Key, "configencryptionkey", utils.LookupEnv("CONFIG_ENCRYPTION_KEY"), "provide the 32 byte key to decrypt the config file")

	f.flagSetAddWifiSettings.StringVar(&f.configContent, "config", "", "specify a config file or smb: file share URL")
	f.flagSetAddWifiSettings.StringVar(&configJson, "configJson", "", "configuration as a JSON string")
	f.flagSetAddWifiSettings.StringVar(&secretsFilePath, "secrets", "", "specify a secrets file ")

	// Params for entering a single wifi config from command line
	wifiCfg := config.WifiConfig{}
	ieee8021xCfg := config.Ieee8021xConfig{}
	eaSettings := config.EnterpriseAssistant{}

	f.flagSetAddWifiSettings.BoolVar(&f.LocalConfig.WiFiSyncEnabled, "wifiSyncEnabled", false, "Enable WiFi synchronization")
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.ProfileName, "profileName", "", "specify wifi profile name name")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.AuthenticationMethod, "authenticationMethod", 0, "specify authentication method")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.EncryptionMethod, "encryptionMethod", 0, "specify encryption method")
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.SSID, "ssid", "", "specify ssid")
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.PskPassphrase, "pskPassphrase", utils.LookupEnv("PSK_PASSPHRASE"), "specify psk passphrase")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.Priority, "priority", 0, "specify priority")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.Username, "username", "", "specify username")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.Password, "ieee8021xPassword", utils.LookupEnv("IEE8021X_PASSWORD"), "8021x password if authenticationProtocol is PEAPv0/EAP-MSCHAPv2(2)")
	f.flagSetAddWifiSettings.IntVar(&ieee8021xCfg.AuthenticationProtocol, "authenticationProtocol", 0, "specify authentication protocol")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.ClientCert, "clientCert", "", "specify client certificate")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.CACert, "caCert", "", "specify CA certificate")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.PrivateKey, "privateKey", utils.LookupEnv("IEE8021X_PRIVATE_KEY"), "specify private key")
	f.flagSetAddWifiSettings.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetAddWifiSettings.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetAddWifiSettings.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetAddWifiSettings.StringVar(&f.Password, "password", utils.LookupEnv("AMT_PASSWORD"), "AMT password")
	f.flagSetAddWifiSettings.StringVar(&eaSettings.EAAddress, "eaAddress", "", "Enterprise Assistant address")
	f.flagSetAddWifiSettings.StringVar(&eaSettings.EAUsername, "eaUsername", "", "Enterprise Assistant username")
	f.flagSetAddWifiSettings.StringVar(&eaSettings.EAPassword, "eaPassword", "", "Enterprise Assistant password")

	// rpc configure wireless is not enough parameters, need -config or a combination of command line flags
	if len(f.commandLineArgs[3:]) == 0 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	// rpc configure wireless -configstring "{ prop: val, prop2: val }"
	// rpc configure add -config "filename" -secrets "someotherfile"
	if err = f.flagSetAddWifiSettings.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	if wifiCfg.ProfileName != "" {
		authMethod := wifi.AuthenticationMethod(wifiCfg.AuthenticationMethod)
		if authMethod == wifi.AuthenticationMethodWPAIEEE8021x ||
			authMethod == wifi.AuthenticationMethodWPA2IEEE8021x {
			// reuse profilename as configuration reference
			wifiCfg.Ieee8021xProfileName = wifiCfg.ProfileName
			ieee8021xCfg.ProfileName = wifiCfg.ProfileName
		}
	}

	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfg)
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfg)
	f.LocalConfig.EnterpriseAssistant = eaSettings
	eaSettings.EAConfigured = false

	if f.configContentV2 != "" && f.configV2Key != "" {
		f.LocalConfig.WiFiSyncEnabled = f.LocalConfigV2.Configuration.Network.Wireless.WiFiSyncEnabled
		f.LocalConfig.WifiConfigs = []config.WifiConfig{}
		f.LocalConfig.Ieee8021xConfigs = []config.Ieee8021xConfig{}
		f.LocalConfig.EnterpriseAssistant = config.EnterpriseAssistant{EAConfigured: false}

		err := f.handleLocalConfigV2()
		if err != nil {
			return utils.FailedReadingConfiguration
		}

		f.LocalConfig.Password = f.LocalConfigV2.Configuration.AMTSpecific.AdminPassword

		for _, wifiCfg := range f.LocalConfigV2.Configuration.Network.Wireless.Profiles {
			authMethod, err := f.getAuthenticationCode(wifiCfg.AuthenticationMethod)
			if err != nil {
				log.Error("Failed to get authentication code", err)
				return err
			}

			encryptionMethod, err := f.getEncrytionCode(wifiCfg.EncryptionMethod)
			if err != nil {
				log.Error("Failed to get encryption code", err)
				return err
			}

			newWifiConfig := config.WifiConfig{
				ProfileName:          wifiCfg.ProfileName,
				SSID:                 wifiCfg.SSID,
				Priority:             wifiCfg.Priority,
				AuthenticationMethod: authMethod,
				EncryptionMethod:     encryptionMethod,
				PskPassphrase:        wifiCfg.Password,
			}

			// Handle 802.1x configurations
			if newWifiConfig.AuthenticationMethod == int(wifi.AuthenticationMethodWPAIEEE8021x) || newWifiConfig.AuthenticationMethod == int(wifi.AuthenticationMethodWPA2IEEE8021x) {
				// Add corresponding 802.1x config
				ieee8021xConfig := config.Ieee8021xConfig{
					ProfileName:            newWifiConfig.ProfileName,
					Username:               wifiCfg.IEEE8021x.Username,
					Password:               wifiCfg.IEEE8021x.Password,
					AuthenticationProtocol: wifiCfg.IEEE8021x.AuthenticationProtocol,
					ClientCert:             wifiCfg.IEEE8021x.ClientCert,
					CACert:                 wifiCfg.IEEE8021x.CACert,
					PrivateKey:             wifiCfg.IEEE8021x.PrivateKey,
				}
				newWifiConfig.Ieee8021xProfileName = newWifiConfig.ProfileName

				f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xConfig)

				if !f.LocalConfig.EnterpriseAssistant.EAConfigured {
					f.LocalConfig.EnterpriseAssistant.EAAddress = f.LocalConfigV2.Configuration.EnterpriseAssistant.URL
					f.LocalConfig.EnterpriseAssistant.EAUsername = f.LocalConfigV2.Configuration.EnterpriseAssistant.Username
					f.LocalConfig.EnterpriseAssistant.EAPassword = f.LocalConfigV2.Configuration.EnterpriseAssistant.Password
					f.LocalConfig.EnterpriseAssistant.EAConfigured = true
				}
			}

			f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, newWifiConfig)
		}
	} else {
		err = f.handleLocalConfig()
		if err != nil {
			return utils.FailedReadingConfiguration
		}

		if configJson != "" {
			err := json.Unmarshal([]byte(configJson), &f.LocalConfig)
			if err != nil {
				log.Error(err)
				return utils.IncorrectCommandLineParameters
			}
		}
	}

	if len(f.LocalConfig.WifiConfigs) == 0 {
		log.Error("missing wifi configuration")
		return utils.MissingOrInvalidConfiguration
	}

	if secretsFilePath != "" {
		err = cleanenv.ReadConfig(secretsFilePath, &wifiSecretConfig)
		if err != nil {
			log.Error("error reading secrets file: ", err)
			return utils.FailedReadingConfiguration
		}
	}

	// merge secrets with configs
	err = f.mergeWifiSecrets(wifiSecretConfig)
	if err != nil {
		return err
	}

	// prompt for missing secrets
	err = f.promptForSecrets()
	if err != nil {
		return err
	}
	// verify configs
	err = f.verifyWifiConfigurations()
	if err != nil {
		return err
	}

	return nil
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

func (f *Flags) mergeWifiSecrets(wifiSecretConfig config.SecretConfig) error {
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

	return nil
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
