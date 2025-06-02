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

	return nil
}
