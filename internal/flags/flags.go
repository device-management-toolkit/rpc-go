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
	"strings"
	"time"

	configv2 "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/security"
	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/internal/smb"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/ilyakaznacheev/cleanenv"
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
	SkipAmtCertCheck                    bool
	Verbose                             bool
	Force                               bool
	JsonOutput                          bool
	RandomPassword                      bool
	Local                               bool
	PartialUnprovision                  bool
	StaticPassword                      string
	Password                            string
	NewPassword                         string
	MPSCert                             string
	MPSPassword                         string
	MPSAddress                          string
	EnvironmentDetection                []string
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
	amtMaintenanceSyncIPCommand         *flag.FlagSet
	amtMaintenanceSyncClockCommand      *flag.FlagSet
	amtMaintenanceSyncHostnameCommand   *flag.FlagSet
	amtMaintenanceChangePasswordCommand *flag.FlagSet
	amtMaintenanceSyncDeviceInfoCommand *flag.FlagSet
	AmtCommand                          amt.AMTCommand
	netEnumerator                       NetEnumerator
	IpConfiguration                     IPConfiguration
	HostnameInfo                        HostnameInfo
	AMTTimeoutDuration                  time.Duration
	FriendlyName                        string
	SkipIPRenew                         bool
	SambaService                        smb.ServiceInterface
	ConfigTLSInfo                       ConfigTLSInfo
	passwordReader                      utils.PasswordReader
	LocalTlsEnforced                    bool
	ControlMode                         int
}

func NewFlags(args []string, pr utils.PasswordReader) *Flags {
	flags := &Flags{}
	flags.passwordReader = pr
	flags.commandLineArgs = args

	flags.amtMaintenanceSyncIPCommand = flag.NewFlagSet(utils.SubCommandSyncIP, flag.ContinueOnError)
	flags.amtMaintenanceSyncClockCommand = flag.NewFlagSet(utils.SubCommandSyncClock, flag.ContinueOnError)
	flags.amtMaintenanceSyncHostnameCommand = flag.NewFlagSet(utils.SubCommandSyncHostname, flag.ContinueOnError)
	flags.amtMaintenanceChangePasswordCommand = flag.NewFlagSet(utils.SubCommandChangePassword, flag.ContinueOnError)
	flags.amtMaintenanceSyncDeviceInfoCommand = flag.NewFlagSet(utils.SubCommandSyncDeviceInfo, flag.ContinueOnError)

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
	case utils.CommandMaintenance:
		err = f.handleMaintenanceCommand()
	default:
		err = utils.IncorrectCommandLineParameters

		f.printUsage()
	}

	return err
}

func (f *Flags) printUsage() string {
	executable := filepath.Base(os.Args[0])
	usage := utils.HelpHeader
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
		f.amtMaintenanceChangePasswordCommand,
		f.amtMaintenanceSyncDeviceInfoCommand,
		f.amtMaintenanceSyncClockCommand,
		f.amtMaintenanceSyncHostnameCommand,
		f.amtMaintenanceSyncIPCommand} {
		fs.StringVar(&f.URL, "u", "", "Websocket address of server to activate against") //required
		fs.BoolVar(&f.SkipCertCheck, "n", false, "Skip Websocket server certificate verification")
		fs.BoolVar(&f.SkipAmtCertCheck, "skipamtcertcheck", false, "Skip AMT ODCA certificate verification")
		fs.StringVar(&f.Proxy, "p", "", "Proxy address and port")
		fs.StringVar(&f.Token, "token", "", "JWT Token for Authorization")
		fs.StringVar(&f.TenantID, "tenant", "", "TenantID")
		fs.StringVar(&f.LMSAddress, "lmsaddress", utils.LMSAddress, "LMS address. Can be used to change location of LMS for debugging.")
		fs.StringVar(&f.LMSPort, "lmsport", utils.LMSPort, "LMS port")
		fs.BoolVar(&f.Verbose, "v", false, "Verbose output")
		fs.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
		fs.BoolVar(&f.JsonOutput, "json", false, "JSON output")
		fs.StringVar(&f.Password, "password", utils.LookupEnv("AMT_PASSWORD"), "AMT password")
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
