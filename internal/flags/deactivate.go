/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

func (f *Flags) handleDeactivateCommand() error {
	f.amtDeactivateCommand.BoolVar(&f.Local, "local", false, "Execute command to AMT directly without cloud interaction")
	f.amtDeactivateCommand.BoolVar(&f.PartialUnprovision, "partial", false, "Partially unprovision the device. Only supported w/ -local flag.")
	f.amtDeactivateCommand.StringVar(&f.configContentV2, "configv2", "", "specify a config file for ACM deactivation")
	f.amtDeactivateCommand.StringVar(&f.configV2Key, "configencryptionkey", utils.LookupEnv("CONFIG_ENCRYPTION_KEY"), "provide the 32 byte key to decrypt the config file")

	if len(f.commandLineArgs) == 2 {
		f.amtDeactivateCommand.PrintDefaults()

		return utils.IncorrectCommandLineParameters
	}

	if err := f.amtDeactivateCommand.Parse(f.commandLineArgs[2:]); err != nil {
		return utils.IncorrectCommandLineParameters
	}

	if f.Local && f.URL != "" {
		fmt.Println("provide either a 'url' or a 'local', but not both")

		return utils.InvalidParameterCombination
	}

	if !f.Local {
		if f.PartialUnprovision {
			fmt.Println("Partial unprovisioning is only supported with local flag")

			return utils.InvalidParameterCombination
		}

		if f.URL == "" {
			fmt.Println("-u flag is required and cannot be empty")
			f.amtDeactivateCommand.Usage()

			return utils.MissingOrIncorrectURL
		}

		if f.Password == "" {
			if err := f.ReadPasswordFromUser(); err != nil {
				return utils.MissingOrIncorrectPassword
			}
		}
	}

	// Load profile if provided for local deactivation
	if f.Local && f.configContentV2 != "" {
		if err := f.handleLocalConfigV2(); err != nil {
			return err
		}

		// Extract provisioning certificate from profile for ACM deactivation
		if f.LocalConfigV2.Configuration.AMTSpecific.ProvisioningCert != "" {
			f.LocalConfig.ACMSettings.ProvisioningCert = f.LocalConfigV2.Configuration.AMTSpecific.ProvisioningCert
		}

		if f.LocalConfigV2.Configuration.AMTSpecific.ProvisioningCertPwd != "" {
			f.LocalConfig.ACMSettings.ProvisioningCertPwd = f.LocalConfigV2.Configuration.AMTSpecific.ProvisioningCertPwd
		}
	}

	return nil
}
