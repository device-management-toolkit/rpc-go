/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package flags

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ilyakaznacheev/cleanenv"
	configv2 "github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/security"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/amt"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/config"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/smb"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// A NetEnumerator enumerates local IP addresses.
type NetEnumerator struct {
	Interfaces     func() ([]net.Interface, error)
	InterfaceAddrs func(*net.Interface) ([]net.Addr, error)
}

type IPConfiguration struct {
	DHCP         bool   `json:"dhcp"`
	Static       bool   `json:"static"`
	IpSync       bool   `json:"ipsync"`
	IpAddress    string `json:"ipAddress"`
	Netmask      string `json:"netmask"`
	Gateway      string `json:"gateway"`
	PrimaryDns   string `json:"primaryDns"`
	SecondaryDns string `json:"secondaryDns"`
}

type HostnameInfo struct {
	DnsSuffixOS string `json:"dnsSuffixOS"`
	Hostname    string `json:"hostname"`
}

// Flags holds data received from the command line
type Flags struct {
	commandLineArgs                     []string
	URL                                 string
	DNS                                 string
	Hostname                            string
	Proxy                               string
	Command                             string
	SubCommand                          string
	Profile                             string
	LMSAddress                          string
	LMSPort                             string
	SkipCertCheck                       bool
	Verbose                             bool
	Force                               bool
	JsonOutput                          bool
	RandomPassword                      bool
	Local                               bool
	PartialUnprovision                  bool
	StaticPassword                      string
	Password                            string
	NewPassword                         string
	LogLevel                            string
	Token                               string
	TenantID                            string
	UseCCM                              bool
	UseACM                              bool
	EchoPass                            bool
	configContent                       string
	configContentV2                     string
	configV2Key                         string
	UUID                                string
	LocalConfig                         config.Config
	LocalConfigV2                       configv2.Configuration
	amtInfoCommand                      *flag.FlagSet
	amtActivateCommand                  *flag.FlagSet
	amtDeactivateCommand                *flag.FlagSet
	amtMaintenanceSyncIPCommand         *flag.FlagSet
	amtMaintenanceSyncClockCommand      *flag.FlagSet
	amtMaintenanceSyncHostnameCommand   *flag.FlagSet
	amtMaintenanceChangePasswordCommand *flag.FlagSet
	amtMaintenanceSyncDeviceInfoCommand *flag.FlagSet
	versionCommand                      *flag.FlagSet
	flagSetAddEthernetSettings          *flag.FlagSet
	flagSetAddWifiSettings              *flag.FlagSet
	flagSetEnableWifiPort               *flag.FlagSet
	flagSetMEBx                         *flag.FlagSet
	flagSetAMTFeatures                  *flag.FlagSet
	AmtCommand                          amt.AMTCommand
	netEnumerator                       NetEnumerator
	IpConfiguration                     IPConfiguration
	HostnameInfo                        HostnameInfo
	AMTTimeoutDuration                  time.Duration
	FriendlyName                        string
	AmtInfo                             AmtInfoFlags
	SkipIPRenew                         bool
	SambaService                        smb.ServiceInterface
	MEBxPassword                        string
	ConfigTLSInfo                       ConfigTLSInfo
	passwordReader                      utils.PasswordReader
	UserConsent                         string
	KVM                                 bool
	SOL                                 bool
	IDER                                bool
	LocalTlsEnforced                    bool
	ControlMode                         int
}

func NewFlags(args []string, pr utils.PasswordReader) *Flags {
	flags := &Flags{}
	flags.passwordReader = pr
	flags.commandLineArgs = args
	flags.amtInfoCommand = flag.NewFlagSet(utils.CommandAMTInfo, flag.ContinueOnError)
	flags.amtInfoCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.amtActivateCommand = flag.NewFlagSet(utils.CommandActivate, flag.ContinueOnError)
	flags.amtDeactivateCommand = flag.NewFlagSet(utils.CommandDeactivate, flag.ContinueOnError)

	flags.amtMaintenanceSyncIPCommand = flag.NewFlagSet(utils.SubCommandSyncIP, flag.ContinueOnError)
	flags.amtMaintenanceSyncClockCommand = flag.NewFlagSet(utils.SubCommandSyncClock, flag.ContinueOnError)
	flags.amtMaintenanceSyncHostnameCommand = flag.NewFlagSet(utils.SubCommandSyncHostname, flag.ContinueOnError)
	flags.amtMaintenanceChangePasswordCommand = flag.NewFlagSet(utils.SubCommandChangePassword, flag.ContinueOnError)
	flags.amtMaintenanceSyncDeviceInfoCommand = flag.NewFlagSet(utils.SubCommandSyncDeviceInfo, flag.ContinueOnError)

	flags.versionCommand = flag.NewFlagSet(utils.CommandVersion, flag.ContinueOnError)
	flags.versionCommand.BoolVar(&flags.JsonOutput, "json", false, "json output")

	flags.flagSetAddEthernetSettings = flag.NewFlagSet(utils.SubCommandWired, flag.ContinueOnError)
	flags.flagSetAddWifiSettings = flag.NewFlagSet(utils.SubCommandWireless, flag.ContinueOnError)
	flags.flagSetEnableWifiPort = flag.NewFlagSet(utils.SubCommandEnableWifiPort, flag.ContinueOnError)
	flags.flagSetMEBx = flag.NewFlagSet(utils.SubCommandSetMEBx, flag.ContinueOnError)
	flags.flagSetAMTFeatures = flag.NewFlagSet(utils.SubCommandSetAMTFeatures, flag.ContinueOnError)

	flags.AmtCommand = amt.NewAMTCommand()
	flags.netEnumerator = NetEnumerator{}
	flags.netEnumerator.Interfaces = net.Interfaces
	flags.netEnumerator.InterfaceAddrs = (*net.Interface).Addrs
	flags.setupCommonFlags()

	flags.SambaService = smb.NewSambaService(utils.PR)

	return flags
}

// ParseFlags is used for understanding the command line flags
func (f *Flags) ParseFlags() error {
	var err error

	if len(f.commandLineArgs) > 1 {
		f.Command = f.commandLineArgs[1]
	}

	switch f.Command {
	case utils.CommandAMTInfo:
		err = f.handleAMTInfo(f.amtInfoCommand)
	case utils.CommandActivate:
		err = f.handleActivateCommand()
	case utils.CommandDeactivate:
		err = f.handleDeactivateCommand()
	case utils.CommandMaintenance:
		err = f.handleMaintenanceCommand()
	case utils.CommandVersion:
		err = f.handleVersionCommand()
	case utils.CommandConfigure:
		err = f.handleConfigureCommand()
	default:
		err = utils.IncorrectCommandLineParameters

		f.printUsage()
	}

	return err
}

func (f *Flags) printUsage() string {
	executable := filepath.Base(os.Args[0])
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"
	usage = usage + "Usage: " + executable + " COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Commands:\n"
	usage = usage + "  activate    Activate this device with a specified profile\n"
	usage = usage + "              Example: " + executable + " activate -u wss://server/activate --profile acmprofile\n"
	usage = usage + "  amtinfo     Displays information about AMT status and configuration\n"
	usage = usage + "              Example: " + executable + " amtinfo\n"
	usage = usage + "  configure   Local configuration of a feature on this device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " configure " + utils.SubCommandWireless + " ...\n"
	usage = usage + "  deactivate  Deactivates this device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " deactivate -u wss://server/activate\n"
	usage = usage + "  maintenance Execute a maintenance task for the device. AMT password is required\n"
	usage = usage + "              Example: " + executable + " maintenance syncclock -u wss://server/activate \n"
	usage = usage + "  version     Displays the current version of RPC and the RPC Protocol version\n"
	usage = usage + "              Example: " + executable + " version\n"
	usage = usage + "\nRun '" + executable + " COMMAND' for more information on a command.\n"
	fmt.Println(usage)

	return usage
}

func (f *Flags) setupCommonFlags() {
	for _, fs := range []*flag.FlagSet{
		f.amtActivateCommand,
		f.amtDeactivateCommand,
		f.amtMaintenanceChangePasswordCommand,
		f.amtMaintenanceSyncDeviceInfoCommand,
		f.amtMaintenanceSyncClockCommand,
		f.amtMaintenanceSyncHostnameCommand,
		f.amtMaintenanceSyncIPCommand} {
		fs.StringVar(&f.URL, "u", "", "Websocket address of server to activate against") //required
		fs.BoolVar(&f.SkipCertCheck, "n", false, "Skip Websocket server certificate verification")
		fs.StringVar(&f.Proxy, "p", "", "Proxy address and port")
		fs.StringVar(&f.Token, "token", "", "JWT Token for Authorization")
		fs.StringVar(&f.TenantID, "tenant", "", "TenantID")
		fs.StringVar(&f.LMSAddress, "lmsaddress", utils.LMSAddress, "LMS address. Can be used to change location of LMS for debugging.")
		fs.StringVar(&f.LMSPort, "lmsport", utils.LMSPort, "LMS port")
		fs.BoolVar(&f.Verbose, "v", false, "Verbose output")
		fs.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
		fs.BoolVar(&f.JsonOutput, "json", false, "JSON output")
		fs.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
		fs.BoolVar(&f.EchoPass, "echo-password", false, "echos AMT Password to the terminal during input")
		fs.DurationVar(&f.AMTTimeoutDuration, "t", 2*time.Minute, "AMT timeout - time to wait until AMT is ready (ex. '2m' or '30s')")

		if fs.Name() != utils.CommandActivate { // activate does not use the -f flag
			fs.BoolVar(&f.Force, "f", false, "Force even if device is not registered with a server")
		}

		if fs.Name() != utils.CommandDeactivate { // activate does not use the -f flag
			fs.StringVar(&f.UUID, "uuid", "", "override AMT device uuid for use with non-CIRA workflow")
		}
	}
}
func (f *Flags) validateUUIDOverride() error {
	_, err := uuid.Parse(f.UUID)
	if err != nil {
		fmt.Println("uuid provided does not follow proper uuid format:", err)
		return err
	}

	return nil
}

func (f *Flags) lookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return defaultVal
}
func (f *Flags) lookupEnvOrBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		parsedVal, err := strconv.ParseBool(val)
		if err != nil {
			log.Error(err)
			return false
		}

		return parsedVal
	}

	return defaultVal
}

func (f *Flags) PromptUserInput(prompt string, value *string) error {
	fmt.Println(prompt)

	_, err := fmt.Scanln(value)
	if err != nil {
		log.Error(err)
		return utils.InvalidUserInput
	}

	return nil
}

func (f *Flags) ReadNewPasswordTo(saveLocation *string, promptPhrase string) error {
	var password, confirmPassword string

	var err error

	fmt.Printf("Please enter %s: \n", promptPhrase)

	password, err = f.passwordReader.ReadPassword()
	if password == "" || err != nil {
		return utils.MissingOrIncorrectPassword
	}

	fmt.Printf("Please confirm %s: \n", promptPhrase)

	confirmPassword, err = f.passwordReader.ReadPassword()
	if password != confirmPassword || err != nil {
		return utils.PasswordsDoNotMatch
	}

	*saveLocation = password

	return nil
}

func (f *Flags) ReadPasswordFromUser() error {
	fmt.Println("Please enter AMT Password: ")

	var password string

	var err error
	if f.EchoPass {
		_, err = fmt.Scanln(&password)
	} else {
		password, err = f.passwordReader.ReadPassword()
	}

	if password == "" || err != nil {
		return utils.MissingOrIncorrectPassword
	}

	f.Password = password

	return nil
}

func (f *Flags) handleLocalConfig() error {
	if f.configContent == "" {
		return nil
	}

	err := utils.FailedReadingConfiguration
	ext := filepath.Ext(strings.ToLower(f.configContent))
	isPFX := ext == ".pfx"

	if strings.HasPrefix(f.configContent, "smb:") {
		isJSON := ext == ".json"
		isYAML := ext == ".yaml" || ext == ".yml"

		if !isPFX && !isJSON && !isYAML {
			log.Error("remote config unsupported smb file extension: ", ext)
			return err
		}

		configBytes, err := f.SambaService.FetchFileContents(f.configContent)
		if err != nil {
			log.Error("config error: ", err)
			return utils.FailedReadingConfiguration
		}

		if isPFX {
			f.LocalConfig.ACMSettings.ProvisioningCert = base64.StdEncoding.EncodeToString(configBytes)
		}

		if isJSON {
			err = cleanenv.ParseJSON(bytes.NewReader(configBytes), &f.LocalConfig)
		}

		if isYAML {
			err = cleanenv.ParseYAML(bytes.NewReader(configBytes), &f.LocalConfig)
		}

		if err != nil {
			log.Error("config error: ", err)
			return err
		}
	} else if isPFX {
		pfxBytes, err := os.ReadFile(f.configContent)
		if err != nil {
			log.Error("config error: ", err)
			return utils.FailedReadingConfiguration
		}

		f.LocalConfig.ACMSettings.ProvisioningCert = base64.StdEncoding.EncodeToString(pfxBytes)
	} else {
		err := cleanenv.ReadConfig(f.configContent, &f.LocalConfig)
		if err != nil {
			log.Error("config error: ", err)
			return err
		}
	}

	return nil
}

func (f *Flags) handleLocalConfigV2() error {
	if f.configV2Key == "" {
		log.Error("config error: missing encryption key")
		return utils.FailedReadingConfiguration
	}

	security := security.Crypto{EncryptionKey: f.configV2Key}

	content, err := security.ReadAndDecryptFile(f.configContentV2)
	if err != nil {
		log.Error("config error: ", err)
		return err
	}

	_, err = json.MarshalIndent(content, "", "  ")
	if err != nil {
		log.Error("error formatting config content: ", err)
		return err
	}

	f.LocalConfigV2 = content

	return nil
}
