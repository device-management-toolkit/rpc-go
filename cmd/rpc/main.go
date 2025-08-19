/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"os"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/internal/cli"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/internal/rps"
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

func runRPC(args []string) error {
	flags, err := parseCommandLine(args)
	if err != nil {
		return err
	}
	// Update TLS enforcement and Current Activation Mode, helps decide how to connect to LMS
	err = updateConnectionSettings(flags)
	if err != nil {
		return err
	}

	err = rps.ExecuteCommand(flags)

	return err
}

func fetchProfile(flags *flags.Flags) error {
	return nil
}

func parseCommandLine(args []string) (*flags.Flags, error) {
	//process flags
	flags := flags.NewFlags(args, utils.PR)
	err := flags.ParseFlags()

	if flags.Verbose {
		log.SetLevel(log.TraceLevel)
	} else {
		lvl, err := log.ParseLevel(flags.LogLevel)
		if err != nil {
			log.Warn(err)
			log.SetLevel(log.InfoLevel)
		} else {
			log.SetLevel(lvl)
		}
	}

	if flags.JsonOutput {
		log.SetFormatter(&log.JSONFormatter{
			DisableHTMLEscape: true,
		})
	} else {
		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
	}

	return flags, err
}

func main() {
	// Check for profile orchestration flag
	if len(os.Args) > 1 && (os.Args[1] == "--profile" || os.Args[1] == "-profile") {
		if len(os.Args) < 3 {
			log.Error("Profile path required when using --profile flag")
			os.Exit(1)
		}

		profilePath := os.Args[2]
		log.Infof("Executing profile orchestration from: %s", profilePath)

		err := checkAccess()
		if err != nil {
			log.Error(AccessErrMsg)
			handleErrorAndExit(err)
		}

		err = cli.ExecuteProfile(profilePath)
		if err != nil {
			log.Errorf("Profile orchestration failed: %v", err)
			handleErrorAndExit(err)
		}

		return
	}

	// Check if this is a Kong command (amtinfo or version)
	if len(os.Args) > 1 && isKongCommand(os.Args[1]) {
		// Use Kong CLI for supported commands
		err := cli.Execute(os.Args)
		if err != nil {
			handleErrorAndExit(err)
		}

		return
	}

	// Use original CLI for all other commands
	err := checkAccess()
	if err != nil {
		log.Error(AccessErrMsg)
		handleErrorAndExit(err)
	}

	err = runRPC(os.Args)
	if err != nil {
		handleErrorAndExit(err)
	}
}

func isKongCommand(cmd string) bool {
	// Only run Kong for the commands we've implemented
	kongCommands := []string{"amtinfo", "version", "deactivate", "activate", "configure"}
	for _, kongCmd := range kongCommands {
		if strings.EqualFold(cmd, kongCmd) {
			return true
		}
	}

	return false
}

func updateConnectionSettings(flags *flags.Flags) error {
	// Check if TLS is Mandatory for LMS connection
	resp, err := flags.AmtCommand.GetChangeEnabled()
	flags.LocalTlsEnforced = false

	if err != nil {
		if err.Error() == "wait timeout while sending data" {
			log.Trace("Operation timed out while sending data. This may occur on systems with AMT version 11 and below.")

			return nil
		} else {
			log.Error(err)

			return err
		}
	}

	if resp.IsTlsEnforcedOnLocalPorts() {
		flags.LocalTlsEnforced = true

		log.Trace("TLS is enforced on local ports")
	}
	// Check the current provisioning mode
	flags.ControlMode, err = flags.AmtCommand.GetControlMode()
	if err != nil {
		return err
	}

	return nil
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
