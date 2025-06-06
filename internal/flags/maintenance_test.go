/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestPrintMaintenanceUsage(t *testing.T) {
	executable := filepath.Base(os.Args[0])
	args := []string{executable}
	flags := NewFlags(args, MockPRSuccess)
	output := flags.printMaintenanceUsage()
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
	assert.Equal(t, usage, output)
}

func TestParseFlagsMaintenance(t *testing.T) {
	argUrl := "-u wss://localhost"
	argCurPw := "-password " + trickyPassword
	newPassword := trickyPassword + "123"
	cmdBase := "./rpc maintenance"

	ipCfgNoParams := IPConfiguration{
		IpAddress: "192.168.1.1",
		Netmask:   "255.255.255.0",
	}
	ipCfgWithParams := IPConfiguration{
		IpAddress:    "10.20.30.40",
		Netmask:      "255.0.0.0",
		Gateway:      "10.0.0.0",
		PrimaryDns:   "8.8.8.8",
		SecondaryDns: "4.4.4.4",
	}
	ipCfgWithLookup := IPConfiguration{
		IpAddress:    ipCfgNoParams.IpAddress,
		Netmask:      ipCfgNoParams.Netmask,
		Gateway:      "10.0.0.0",
		PrimaryDns:   "1.2.3.4",
		SecondaryDns: "5.6.7.8",
	}
	tests := map[string]struct {
		cmdLine      string
		wantResult   error
		wantIPConfig IPConfiguration
		passwordFail bool
	}{
		"should pass with usage - no additional arguments": {
			cmdLine:    cmdBase,
			wantResult: utils.IncorrectCommandLineParameters,
		},
		"should fail with usage - unhandled task": {
			cmdLine:    cmdBase + " someothertask",
			wantResult: utils.IncorrectCommandLineParameters,
		},
		"should fail - required websocket URL": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncClock + " " + argCurPw,
			wantResult: utils.MissingOrIncorrectURL,
		},
		"should fail - required amt password": {
			cmdLine:      cmdBase + " " + utils.SubCommandSyncClock + " " + argUrl,
			wantResult:   utils.MissingOrIncorrectPassword,
			passwordFail: true,
		},
		"should pass - syncclock": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncClock + " " + argUrl + " " + argCurPw,
			wantResult: nil,
		},
		"should fail - syncclock bad param": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncClock + " -nope " + argUrl + " " + argCurPw,
			wantResult: utils.IncorrectCommandLineParameters,
		},
		"should pass - synchostname no params": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncHostname + " " + argUrl + " " + argCurPw,
			wantResult: nil,
		},
		"should pass - task force flag": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncHostname + " -f " + argUrl + " " + argCurPw,
			wantResult: nil,
		},
		"should fail - synchostname bad param": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncHostname + " -nope " + argUrl + " " + argCurPw,
			wantResult: utils.IncorrectCommandLineParameters,
		},
		"should pass - syncdeviceinfo": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncDeviceInfo + " " + argUrl + " " + argCurPw,
			wantResult: nil,
		},
		"should fail - syncdeviceinfo bad param": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncDeviceInfo + " -nope " + argUrl + " " + argCurPw,
			wantResult: utils.IncorrectCommandLineParameters,
		},
		"should pass - syncip no params": {
			cmdLine:      cmdBase + " " + utils.SubCommandSyncIP + " " + argUrl + " " + argCurPw,
			wantResult:   nil,
			wantIPConfig: ipCfgNoParams,
		},
		"should pass - syncip with params": {
			cmdLine: cmdBase + " " +
				utils.SubCommandSyncIP +
				" -staticip " + ipCfgWithParams.IpAddress +
				" -netmask " + ipCfgWithParams.Netmask +
				" -gateway " + ipCfgWithParams.Gateway +
				" -primarydns " + ipCfgWithParams.PrimaryDns +
				" -secondarydns " + ipCfgWithParams.SecondaryDns +
				" " + argUrl + " " + argCurPw,
			wantResult:   nil,
			wantIPConfig: ipCfgWithParams,
		},
		"should pass - syncip with lookup": {
			cmdLine: cmdBase + " " +
				utils.SubCommandSyncIP +
				" -gateway " + ipCfgWithLookup.Gateway +
				" -primarydns " + ipCfgWithLookup.PrimaryDns +
				" -secondarydns " + ipCfgWithLookup.SecondaryDns +
				" " + argUrl + " " + argCurPw,
			wantResult:   nil,
			wantIPConfig: ipCfgWithLookup,
		},
		"should fail - syncip bad param": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncIP + " -nope " + argUrl + " " + argCurPw,
			wantResult: utils.IncorrectCommandLineParameters,
		},
		"should fail - syncip MissingOrIncorrectNetworkMask": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncIP + " -netmask 322.299.0.0 " + argUrl + " " + argCurPw,
			wantResult: utils.MissingOrIncorrectNetworkMask,
		},
		"should fail - syncip MissingOrIncorrectStaticIP": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncIP + " -staticip 322.299.0.0 " + argUrl + " " + argCurPw,
			wantResult: utils.MissingOrIncorrectStaticIP,
		},
		"should fail - syncip MissingOrIncorrectGateway": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncIP + " -gateway 322.299.0.0 " + argUrl + " " + argCurPw,
			wantResult: utils.MissingOrIncorrectGateway,
		},
		"should fail - syncip MissingOrIncorrectPrimaryDNS": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncIP + " -primarydns 322.299.0.0 " + argUrl + " " + argCurPw,
			wantResult: utils.MissingOrIncorrectPrimaryDNS,
		},
		"should fail - syncip MissingOrIncorrectSecondaryDNS": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncIP + " -secondarydns 322.299.0.0 " + argUrl + " " + argCurPw,
			wantResult: utils.MissingOrIncorrectSecondaryDNS,
		},
		"should pass - changepassword to random value": {
			cmdLine:    cmdBase + " " + utils.SubCommandChangePassword + " " + argUrl + " " + argCurPw,
			wantResult: nil,
		},
		"should pass - changepassword using static value": {
			cmdLine:    cmdBase + " " + utils.SubCommandChangePassword + " -static " + newPassword + " " + argUrl + " " + argCurPw,
			wantResult: nil,
		},
		"should pass - changepassword static value before other flags": {
			cmdLine:    cmdBase + " " + utils.SubCommandChangePassword + " -static " + newPassword + " " + argUrl + " " + argCurPw,
			wantResult: nil,
		},
		"should pass - changepassword static value after all flags": {
			cmdLine:    cmdBase + " " + utils.SubCommandChangePassword + " " + argUrl + " " + argCurPw + " -static " + newPassword,
			wantResult: nil,
		},
		"should fail - changepassword bad param": {
			cmdLine:    cmdBase + " " + utils.SubCommandChangePassword + " -nope " + argUrl + " " + argCurPw,
			wantResult: utils.IncorrectCommandLineParameters,
		},
		"should pass - password user input": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncClock + " " + argUrl,
			wantResult: nil,
		},
		"should pass - UUID Override": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncClock + " " + argUrl + " " + argCurPw + " -uuid 4c2e8db8-1c7a-00ea-279c-d17395b1f584",
			wantResult: nil,
		},
		"should fail - InvalidUUID": {
			cmdLine:    cmdBase + " " + utils.SubCommandSyncClock + " " + argUrl + " " + argCurPw + " -uuid 4c2e8db8-1c7a-00ea-279c",
			wantResult: utils.InvalidUUID,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			flags := NewFlags(args, MockPRSuccess)

			if tc.passwordFail {
				flags = NewFlags(args, MockPRFail)
			}

			flags.AmtCommand.PTHI = MockPTHICommands{}
			flags.netEnumerator = testNetEnumerator
			gotResult := flags.ParseFlags()
			assert.Equal(t, tc.wantResult, gotResult)
			assert.Equal(t, utils.CommandMaintenance, flags.Command)
			assert.Equal(t, tc.wantIPConfig, flags.IpConfiguration)
		})
	}
}
