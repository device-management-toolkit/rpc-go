/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

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

// customTextFormatter formats log entries with pkg before level
type customTextFormatter struct {
	log.TextFormatter
}

func (f *customTextFormatter) Format(entry *log.Entry) ([]byte, error) {
	// Get the base formatted output
	formatted, err := f.TextFormatter.Format(entry)
	if err != nil {
		return nil, err
	}

	output := string(formatted)

	// Find and extract pkg= field
	pkgStart := strings.Index(output, " pkg=")
	if pkgStart == -1 {
		return formatted, nil // No pkg field
	}

	// Find end of pkg field (next space or newline)
	pkgEnd := len(output)
	for i := pkgStart + 1; i < len(output); i++ {
		if output[i] == ' ' || output[i] == '\n' {
			pkgEnd = i
			break
		}
	}

	pkgField := output[pkgStart:pkgEnd]

	// Find level= position
	levelStart := strings.Index(output, " level=")
	if levelStart == -1 {
		return formatted, nil
	}

	// Reconstruct: everything before level + pkg + everything from level to before pkg + everything after pkg
	result := output[:levelStart] + pkgField + " " + output[levelStart+1:pkgStart] + output[pkgEnd:]

	return []byte(result), nil
}

// packageHook adds pkg field to all log entries based on the caller
type packageHook struct{}

func (h *packageHook) Levels() []log.Level {
	return log.AllLevels
}

func (h *packageHook) Fire(entry *log.Entry) error {
	// Determine package from the caller function name
	if entry.Caller != nil {
		funcName := entry.Caller.Function
		if strings.Contains(funcName, "/go-wsman-messages/") {
			entry.Data["pkg"] = "gwsman"
		} else {
			entry.Data["pkg"] = "rpc-go"
		}
	} else {
		entry.Data["pkg"] = "rpc-go"
	}
	return nil
}

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
		log.SetReportCaller(true)
	} else {
		lvl, err := log.ParseLevel(flags.LogLevel)
		if err != nil {
			log.Warn(err)
			log.SetLevel(log.InfoLevel)
		} else {
			log.SetLevel(lvl)
		}
	}

	callerPrettyfier := func(f *runtime.Frame) (string, string) {
		// Extract just the function name (last part after the last /)
		funcName := f.Function
		if idx := strings.LastIndex(funcName, "/"); idx != -1 {
			funcName = funcName[idx+1:]
		}
		// Extract just the filename and line number
		filename := fmt.Sprintf("%s:%d", filepath.Base(f.File), f.Line)
		return funcName, filename
	}

	// Add package field to all logs
	log.AddHook(&packageHook{})

	if flags.JsonOutput {
		log.SetFormatter(&log.JSONFormatter{
			DisableHTMLEscape: true,
			CallerPrettyfier:  callerPrettyfier,
		})
	} else {
		log.SetFormatter(&customTextFormatter{
			TextFormatter: log.TextFormatter{
				DisableColors:    true,
				FullTimestamp:    true,
				CallerPrettyfier: callerPrettyfier,
			},
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
