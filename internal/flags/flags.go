/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package flags

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	configv2 "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/smb"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
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
	commandLineArgs      []string
	URL                  string // used
	DNS                  string // used
	Hostname             string //used
	Proxy                string //used
	Command              string //used
	SubCommand           string
	Profile              string
	SkipCertCheck        bool // used
	SkipAmtCertCheck     bool // used
	Verbose              bool
	Force                bool
	JsonOutput           bool
	RandomPassword       bool
	Local                bool
	PartialUnprovision   bool
	StaticPassword       string
	Password             string //used
	NewPassword          string
	MPSCert              string
	MPSPassword          string
	MPSAddress           string
	EnvironmentDetection []string
	LogLevel             string
	TenantID             string //used
	UseCCM               bool
	UseACM               bool
	EchoPass             bool
	UUID                 string //used
	LocalConfigV2        configv2.Configuration
	AmtCommand           amt.AMTCommand
	netEnumerator        NetEnumerator
	IpConfiguration      IPConfiguration
	HostnameInfo         HostnameInfo  // used
	AMTTimeoutDuration   time.Duration //used
	FriendlyName         string        //used
	SkipIPRenew          bool
	SambaService         smb.ServiceInterface
	passwordReader       utils.PasswordReader
	LocalTlsEnforced     bool //used
	ControlMode          int
}

func NewFlags(args []string, pr utils.PasswordReader) *Flags {
	flags := &Flags{}
	flags.passwordReader = pr
	flags.commandLineArgs = args

	flags.AmtCommand = amt.NewAMTCommand()
	flags.netEnumerator = NetEnumerator{}
	flags.netEnumerator.Interfaces = net.Interfaces
	flags.netEnumerator.InterfaceAddrs = (*net.Interface).Addrs

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
	usage = usage + "  version     Displays the current version of RPC and the RPC Protocol version\n"
	usage = usage + "              Example: " + executable + " version\n"
	usage = usage + "\nRun '" + executable + " COMMAND' for more information on a command.\n"
	fmt.Println(usage)

	return usage
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
