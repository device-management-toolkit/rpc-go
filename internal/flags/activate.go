/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"fmt"
	"reflect"
	"regexp"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (f *Flags) handleActivateCommand() error {
	f.amtActivateCommand.StringVar(&f.DNS, "d", utils.LookupEnv("DNS_SUFFIX"), "dns suffix override")
	f.amtActivateCommand.StringVar(&f.Hostname, "h", utils.LookupEnv("HOSTNAME"), "hostname override")
	f.amtActivateCommand.StringVar(&f.Profile, "profile", utils.LookupEnv("PROFILE"), "name of the profile to use")
	f.amtActivateCommand.BoolVar(&f.Local, "local", false, "activate amt locally")
	f.amtActivateCommand.BoolVar(&f.UseCCM, "ccm", false, "activate in client control mode (CCM)")
	f.amtActivateCommand.BoolVar(&f.UseACM, "acm", false, "activate in admin control mode (ACM)")
	// use the Func call rather than StringVar to keep the default value out of the help/usage message
	f.amtActivateCommand.Func("name", "friendly name to associate with this device", func(flagValue string) error {
		f.FriendlyName = flagValue

		return nil
	})
	f.amtActivateCommand.BoolVar(&f.SkipIPRenew, "skipIPRenew", false, "skip DHCP renewal of the IP address if AMT becomes enabled")
	// for local activation in ACM mode need a few more items
	f.amtActivateCommand.StringVar(&f.configContent, "config", "", "specify a config file or smb: file share URL")
	f.amtActivateCommand.StringVar(&f.configContentV2, "configv2", "", "specify a config file or smb: file share URL")
	f.amtActivateCommand.StringVar(&f.configV2Key, "configencryptionkey", utils.LookupEnv("CONFIG_ENCRYPTION_KEY"), "provide the 32 byte key to decrypt the config file")
	f.amtActivateCommand.StringVar(&f.LocalConfig.ACMSettings.AMTPassword, "amtPassword", utils.LookupEnv("AMT_PASSWORD"), "amt password")
	f.amtActivateCommand.StringVar(&f.LocalConfig.ACMSettings.ProvisioningCert, "provisioningCert", utils.LookupEnv("PROVISIONING_CERT"), "provisioning certificate")
	f.amtActivateCommand.StringVar(&f.LocalConfig.ACMSettings.ProvisioningCertPwd, "provisioningCertPwd", utils.LookupEnv("PROVISIONING_CERT_PASSWORD"), "provisioning certificate password")
	f.amtActivateCommand.BoolVar(&f.LocalConfig.StopConfiguration, "stopConfig", false, "transitions AMT from in-provisioning state back to pre-provisioning state")

	if len(f.commandLineArgs) == 2 {
		f.amtActivateCommand.PrintDefaults()

		return utils.IncorrectCommandLineParameters
	}

	if err := f.amtActivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		re := regexp.MustCompile(`: .*`)
		switch re.FindString(err.Error()) {
		case ": -d":
			err = utils.MissingDNSSuffix
		case ": -p":
			err = utils.MissingProxyAddressAndPort
		case ": -h":
			err = utils.MissingHostname
		case ": -profile":
			err = utils.MissingOrIncorrectProfile
		default:
			err = utils.IncorrectCommandLineParameters
		}

		return err
	}

	if f.LocalConfig.StopConfiguration {
		response, err := f.AmtCommand.StopConfiguration()
		if err != nil {
			return err
		}

		fmt.Println(response)

		return nil
	}

	if f.Local && f.URL != "" {
		fmt.Println("provide either a 'url' or a 'local', but not both")

		return utils.InvalidParameterCombination
	}

	if !f.Local {
		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtActivateCommand.Usage()

			return utils.MissingOrIncorrectURL
		}

		if f.Profile == "" {
			fmt.Println("-profile flag is required and cannot be empty")
			f.amtActivateCommand.Usage()

			return utils.MissingOrIncorrectProfile
		}

		if f.UUID != "" {
			err := f.validateUUIDOverride()
			if err != nil {
				f.amtActivateCommand.Usage()

				return utils.InvalidUUID
			}

			fmt.Println("Warning: Overriding UUID prevents device from connecting to MPS")
		}
	} else {
		if f.configContentV2 != "" {
			err := f.handleLocalConfigV2()
			if err != nil {
				return utils.FailedReadingConfiguration
			}

			err = f.ValidateConfigV2()
			if err != nil {
				return err
			}
		} else {
			err := f.handleLocalConfigV1()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *Flags) handleLocalConfigV1() error {
	if !f.UseCCM && !f.UseACM || f.UseCCM && f.UseACM {
		fmt.Println("must specify -ccm or -acm, but not both")

		return utils.InvalidParameterCombination
	}

	err := f.handleLocalConfig()
	if err != nil {
		return utils.FailedReadingConfiguration
	}

	if f.Password != "" {
		// Set all password fields to command line password
		f.LocalConfig.CCMSettings.AMTPassword = f.Password
		f.LocalConfig.Password = f.Password
	}

	// Use CCM settings password if CCM mode is active
	if f.UseCCM && f.LocalConfig.CCMSettings.AMTPassword != "" {
		f.Password = f.LocalConfig.CCMSettings.AMTPassword
		f.LocalConfig.Password = f.Password
	}

	// Use ACM settings password if ACM mode is active
	if f.UseACM && f.LocalConfig.ACMSettings.AMTPassword != "" {
		f.Password = f.LocalConfig.ACMSettings.AMTPassword
		f.LocalConfig.Password = f.Password
	}

	if f.LocalConfig.Password == "" {
		if rc := f.ReadNewPasswordTo(&f.Password, "New AMT Password"); rc != nil {
			return rc
		}

		f.LocalConfig.Password = f.Password
		f.LocalConfig.ACMSettings.AMTPassword = f.Password
		f.LocalConfig.CCMSettings.AMTPassword = f.Password
	}

	if f.UseACM {
		v := reflect.ValueOf(f.LocalConfig.ACMSettings)
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).Interface() == "" { // not checking 0 since authenticantProtocol can and needs to be 0 for EAP-TLS
				log.Error("Missing value for field: ", v.Type().Field(i).Name)

				return utils.IncorrectCommandLineParameters
			}
		}
	}

	if f.UUID != "" {
		fmt.Println("-uuid cannot be use in local activation")
		f.amtActivateCommand.Usage()

		return utils.InvalidParameterCombination
	}

	return nil
}

func (f *Flags) ValidateConfigV2() error {
	// Check if the Control Mode is set
	switch f.LocalConfigV2.Configuration.AMTSpecific.ControlMode {
	case "acmactivate":
		f.UseACM = true
	case "ccmactivate":
		f.UseCCM = true
	default:
		log.Error("Invalid Control Mode")

		return utils.IncorrectCommandLineParameters
	}

	// Check if the AMT Password is set
	if f.LocalConfigV2.Configuration.AMTSpecific.AdminPassword == "" {
		log.Warn("AMT Password is not set")

		if rc := f.ReadNewPasswordTo(&f.Password, "New AMT Password"); rc != nil {
			return rc
		}
	}

	// Use command line password if provided, otherwise use config password
	pwd := f.LocalConfigV2.Configuration.AMTSpecific.AdminPassword
	if f.Password != "" {
		pwd = f.Password
	}

	// Set both password fields
	f.LocalConfig.ACMSettings.AMTPassword = pwd
	f.LocalConfig.Password = pwd

	if f.UseACM {
		// Check if the Provisioning Certificate is set
		if f.LocalConfigV2.Configuration.AMTSpecific.ProvisioningCert == "" {
			log.Error("Provisioning Certificate is not set")

			return utils.IncorrectCommandLineParameters
		}

		f.LocalConfig.ACMSettings.ProvisioningCert = f.LocalConfigV2.Configuration.AMTSpecific.ProvisioningCert

		// Check if the Provisioning Certificate Password is set
		if f.LocalConfigV2.Configuration.AMTSpecific.ProvisioningCertPwd == "" {
			log.Error("Provisioning Certificate Password is not set")

			return utils.IncorrectCommandLineParameters
		}

		f.LocalConfig.ACMSettings.ProvisioningCertPwd = f.LocalConfigV2.Configuration.AMTSpecific.ProvisioningCertPwd
	}

	return nil
}
