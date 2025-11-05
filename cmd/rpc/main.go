/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"os"

	"github.com/device-management-toolkit/rpc-go/v2/internal/cli"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const AccessErrMsg = "Failed to execute due to access issues. " +
	"Please ensure that Intel ME is present, " +
	"the MEI driver is installed, " +
	"and the runtime has administrator or root privileges."

func checkAccess() error {
	amtCommand := amt.NewAMTCommand()

	err := amtCommand.Initialize()
	if err != nil {
		return err
	}

	return nil
}

func main() {
	err := cli.Execute(os.Args)
	if err != nil {
		handleErrorAndExit(err)
	}
}

func handleErrorAndExit(err error) {
	if customErr, ok := err.(utils.CustomError); ok {
		if err != utils.HelpRequested {
			log.Error(customErr.Error())
		}

		os.Exit(customErr.Code)
	} else {
		log.Error(err.Error())
		os.Exit(utils.GenericFailure.Code)
	}
}
