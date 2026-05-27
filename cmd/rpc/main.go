/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"os"

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/internal/local"
	"github.com/device-management-toolkit/rpc-go/v2/internal/rps"
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

	if flags.Local {
		err = local.ExecuteCommand(flags)
	} else {
		err = rps.ExecuteCommand(flags)
	}

	return err
}

func fetchProfile(flags *flags.Flags) error {
	return nil
}

func parseCommandLine(args []string) (*flags.Flags, error) {
	// process flags
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

func updateConnectionSettings(flags *flags.Flags) error {
	flags.LocalTlsEnforced = false

	controlMode, err := flags.AmtCommand.GetControlMode()
	if err != nil {
		return err
	}

	flags.ControlMode = controlMode

	// Best-effort, non-fatal: the watchdog HECI client may be busy/held by LMS. When it
	// succeeds, cache it and honor local-port TLS enforcement (so WSMAN picks 16993).
	if resp, err := flags.AmtCommand.GetChangeEnabled(); err == nil {
		flags.ChangeEnabled = resp
		flags.ChangeEnabledValid = true

		if resp.IsTlsEnforcedOnLocalPorts() {
			flags.LocalTlsEnforced = true

			log.Trace("TLS is enforced on local ports")
		}
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
