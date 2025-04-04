/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/amt"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (f *Flags) printMaintenanceUsage() string {
	executable := filepath.Base(os.Args[0])
	usage := utils.HelpHeader
	usage = usage + "Usage: " + executable + " maintenance COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Maintenance Commands:\n"
	usage = usage + "  changepassword Change the AMT password. A random password is generated by default. Specify -static to set manually. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance changepassword -u wss://server/activate\n"
	usage = usage + "  syncdeviceinfo Sync device information. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance syncdeviceinfo -u wss://server/activate\n"
	usage = usage + "  syncclock      Sync the host OS clock to AMT. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance syncclock -u wss://server/activate\n"
	usage = usage + "  synchostname   Sync the hostname of the client to AMT. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance synchostname -u wss://server/activate\n"
	usage = usage + "  syncip         Sync the IP configuration of the host OS to AMT Network Settings. AMT password is required\n"
	usage = usage + "                 Example: " + executable + " maintenance syncip -staticip 192.168.1.7 -netmask 255.255.255.0 -gateway 192.168.1.1 -primarydns 8.8.8.8 -secondarydns 4.4.4.4 -u wss://server/activate\n"
	usage = usage + "                 If a static ip is not specified, the ip address and netmask of the host OS is used\n"
	usage = usage + "\nRun '" + executable + " maintenance COMMAND -h' for more information on a command.\n"
	fmt.Println(usage)

	return usage
}

func (f *Flags) handleMaintenanceCommand() error {
	//validation section
	if len(f.commandLineArgs) == 2 {
		f.printMaintenanceUsage()

		return utils.IncorrectCommandLineParameters
	}

	var err error

	f.SubCommand = f.commandLineArgs[2]
	switch f.SubCommand {
	case "syncclock":
		err = f.handleMaintenanceSyncClock()
	case "synchostname":
		err = f.handleMaintenanceSyncHostname()
	case "syncip":
		err = f.handleMaintenanceSyncIP()
	case "changepassword":
		err = f.handleMaintenanceSyncChangePassword()
	case "syncdeviceinfo":
		err = f.handleMaintenanceSyncDeviceInfo()
	default:
		f.printMaintenanceUsage()

		err = utils.IncorrectCommandLineParameters
	}

	if err != nil {
		return err
	}

	if f.Password == "" {
		if err := f.ReadPasswordFromUser(); err != nil {
			return utils.MissingOrIncorrectPassword
		}
	}

	if f.URL == "" {
		fmt.Print("\n-u flag is required and cannot be empty\n\n")
		f.printMaintenanceUsage()

		return utils.MissingOrIncorrectURL
	}

	if f.UUID != "" {
		err := f.validateUUIDOverride()
		if err != nil {
			f.printMaintenanceUsage()

			return utils.InvalidUUID
		}
	}

	return nil
}

func (f *Flags) handleMaintenanceSyncClock() error {
	err := f.amtMaintenanceSyncClockCommand.Parse(f.commandLineArgs[3:])
	if err != nil {
		if err.Error() == utils.HelpRequested.Message {
			return utils.HelpRequested
		}

		return utils.IncorrectCommandLineParameters
	}

	return nil
}

func (f *Flags) handleMaintenanceSyncDeviceInfo() error {
	err := f.amtMaintenanceSyncDeviceInfoCommand.Parse(f.commandLineArgs[3:])
	if err != nil {
		if err.Error() == utils.HelpRequested.Message {
			return utils.HelpRequested
		}

		return utils.IncorrectCommandLineParameters
	}

	return nil
}

func (f *Flags) handleMaintenanceSyncHostname() error {
	var err error

	err = f.amtMaintenanceSyncHostnameCommand.Parse(f.commandLineArgs[3:])
	if err != nil {
		if err.Error() == utils.HelpRequested.Message {
			return utils.HelpRequested
		}

		return utils.IncorrectCommandLineParameters
	}

	amtCommand := amt.NewAMTCommand()
	if f.HostnameInfo.DnsSuffixOS, err = amtCommand.GetOSDNSSuffix(); err != nil {
		log.Error(err)
	}

	f.HostnameInfo.Hostname, err = os.Hostname()
	if err != nil {
		log.Error(err)

		return utils.OSNetworkInterfacesLookupFailed
	} else if f.HostnameInfo.Hostname == "" {
		log.Error("OS hostname is not available")

		return utils.OSNetworkInterfacesLookupFailed
	}

	return nil
}

// wrap the flag.Func method signature with the assignment value
func validateIP(assignee *string) func(string) error {
	return func(val string) error {
		if net.ParseIP(val) == nil {
			return errors.New("not a valid ip address")
		}

		*assignee = val

		return nil
	}
}

func (f *Flags) handleMaintenanceSyncIP() error {
	f.amtMaintenanceSyncIPCommand.Func(
		"staticip",
		"IP address to be assigned to AMT - if not specified, the IP Address of the active OS newtork interface is used",
		validateIP(&f.IpConfiguration.IpAddress))
	f.amtMaintenanceSyncIPCommand.Func(
		"netmask",
		"Network mask to be assigned to AMT - if not specified, the Network mask of the active OS newtork interface is used",
		validateIP(&f.IpConfiguration.Netmask))
	f.amtMaintenanceSyncIPCommand.Func("gateway", "Gateway address to be assigned to AMT", validateIP(&f.IpConfiguration.Gateway))
	f.amtMaintenanceSyncIPCommand.Func("primarydns", "Primary DNS to be assigned to AMT", validateIP(&f.IpConfiguration.PrimaryDns))
	f.amtMaintenanceSyncIPCommand.Func("secondarydns", "Secondary DNS to be assigned to AMT", validateIP(&f.IpConfiguration.SecondaryDns))

	err := f.amtMaintenanceSyncIPCommand.Parse(f.commandLineArgs[3:])
	if err != nil {
		if err.Error() == utils.HelpRequested.Message {
			return utils.HelpRequested
		}
		// Parse the error message to find the problematic flag.
		// The problematic flag is of the following format '-' followed by flag name and then a ':'
		re := regexp.MustCompile(`-.*:`)
		switch re.FindString(err.Error()) {
		case "-netmask:":
			err = utils.MissingOrIncorrectNetworkMask
		case "-staticip:":
			err = utils.MissingOrIncorrectStaticIP
		case "-gateway:":
			err = utils.MissingOrIncorrectGateway
		case "-primarydns:":
			err = utils.MissingOrIncorrectPrimaryDNS
		case "-secondarydns:":
			err = utils.MissingOrIncorrectSecondaryDNS
		default:
			err = utils.IncorrectCommandLineParameters
		}

		return err
	} else if len(f.IpConfiguration.IpAddress) != 0 {
		return nil
	}

	amtLanIfc, err := f.AmtCommand.GetLANInterfaceSettings(false)
	if err != nil {
		log.Error(err)

		return utils.AMTConnectionFailed
	}

	ifaces, err := f.netEnumerator.Interfaces()
	if err != nil {
		log.Error(err)

		return utils.OSNetworkInterfacesLookupFailed
	}

	for _, i := range ifaces {
		if len(f.IpConfiguration.IpAddress) != 0 {
			break
		}

		if i.HardwareAddr.String() != amtLanIfc.MACAddress {
			continue
		}

		addrs, _ := f.netEnumerator.InterfaceAddrs(&i)
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok &&
				ipnet.IP.To4() != nil &&
				!ipnet.IP.IsLoopback() {
				f.IpConfiguration.IpAddress = ipnet.IP.String()
				f.IpConfiguration.Netmask = net.IP(ipnet.Mask).String()
			}
		}
	}

	if len(f.IpConfiguration.IpAddress) == 0 {
		log.Errorf("static ip address not found")

		return utils.OSNetworkInterfacesLookupFailed
	}

	return nil
}

func (f *Flags) handleMaintenanceSyncChangePassword() error {
	f.amtMaintenanceChangePasswordCommand.StringVar(&f.StaticPassword, "static", "", "specify a new password for AMT")

	err := f.amtMaintenanceChangePasswordCommand.Parse(f.commandLineArgs[3:])
	if err != nil {
		if err.Error() == utils.HelpRequested.Message {
			return utils.HelpRequested
		}

		return utils.IncorrectCommandLineParameters
	}

	return nil
}
