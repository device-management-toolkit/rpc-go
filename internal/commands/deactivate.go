/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"crypto/tls"
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/rps"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// Control mode constants for better readability
const (
	ControlModeCCM = 1
	ControlModeACM = 2
)

// readPasswordFromUser prompts the user for a password
func readPasswordFromUser() (string, error) {
	fmt.Print("Please enter AMT Password: ")

	password, err := utils.PR.ReadPassword()
	if err != nil {
		return "", err
	}

	fmt.Println() // Add newline after password input

	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	return password, nil
}

// ensurePasswordProvided ensures a password is available, prompting if necessary
func (cmd *DeactivateCmd) ensurePasswordProvided() error {
	if cmd.Password == "" {
		password, err := readPasswordFromUser()
		if err != nil {
			return utils.MissingOrIncorrectPassword
		}

		cmd.Password = password
	}

	return nil
}

// setupTLSConfig creates TLS configuration if local TLS is enforced
func (cmd *DeactivateCmd) setupTLSConfig(ctx *Context, controlMode int) *tls.Config {
	tlsConfig := &tls.Config{}
	if ctx.LocalTLSEnforced {
		tlsConfig = config.GetTLSConfig(&controlMode, nil, ctx.SkipCertCheck)
	}

	return tlsConfig
}

// DeactivateCmd represents the deactivate command
type DeactivateCmd struct {
	Local              bool   `help:"Execute command to AMT directly without cloud interaction" short:"l"`
	PartialUnprovision bool   `help:"Partially unprovision the device. Only supported with -local flag" name:"partial"`
	URL                string `help:"Server URL for remote deactivation" short:"u"`
	Password           string `help:"AMT Password" env:"AMT_PASSWORD" short:"p"`
}

// Validate implements Kong's extensible validation interface for business logic validation
func (cmd *DeactivateCmd) Validate() error {
	// Ensure either local mode or URL is provided, but not both
	if cmd.Local && cmd.URL != "" {
		return fmt.Errorf("provide either a 'url' or a 'local', but not both")
	}

	// Ensure at least one mode is selected
	if !cmd.Local && cmd.URL == "" {
		return fmt.Errorf("-u flag is required when not using local mode")
	}

	// Business logic validation: partial unprovision only works with local mode
	if cmd.PartialUnprovision && !cmd.Local {
		return fmt.Errorf("partial unprovisioning is only supported with local flag")
	}

	return nil
}

// Run executes the deactivate command
func (cmd *DeactivateCmd) Run(ctx *Context) error {
	if cmd.Local {
		// For local deactivation
		return cmd.executeLocalDeactivate(ctx)
	}

	// For remote deactivation via RPS
	return cmd.executeRemoteDeactivate(ctx)
}

// executeRemoteDeactivate handles remote deactivation via RPS
func (cmd *DeactivateCmd) executeRemoteDeactivate(ctx *Context) error {
	if err := cmd.ensurePasswordProvided(); err != nil {
		return err
	}

	// Create flags object for RPS
	f := &flags.Flags{
		Command:       utils.CommandDeactivate,
		URL:           cmd.URL,
		Password:      cmd.Password,
		LogLevel:      ctx.LogLevel,
		JsonOutput:    ctx.JsonOutput,
		Verbose:       ctx.Verbose,
		SkipCertCheck: ctx.SkipCertCheck,
	}

	// Execute via RPS
	return rps.ExecuteCommand(f)
}

// executeLocalDeactivate handles local deactivation
func (cmd *DeactivateCmd) executeLocalDeactivate(ctx *Context) error {
	controlMode, err := ctx.AMTCommand.GetControlMode()
	if err != nil {
		log.Error(err)

		return utils.AMTConnectionFailed
	}

	// Deactivate based on the control mode
	switch controlMode {
	case ControlModeCCM:
		if cmd.PartialUnprovision {
			return fmt.Errorf("partial unprovisioning is only supported in ACM mode")
		}

		return cmd.deactivateCCM(ctx)
	case ControlModeACM:
		return cmd.deactivateACM(ctx, controlMode)
	default:
		log.Error("Deactivation failed. Device control mode: " + utils.InterpretControlMode(controlMode))

		return utils.UnableToDeactivate
	}
}

// deactivateACM handles ACM mode deactivation
func (cmd *DeactivateCmd) deactivateACM(ctx *Context, controlMode int) error {
	if err := cmd.ensurePasswordProvided(); err != nil {
		return err
	}

	// Setup TLS configuration
	tlsConfig := cmd.setupTLSConfig(ctx, controlMode)

	// Create WSMAN client
	wsmanMessage := localamt.NewGoWSMANMessages(utils.LMSAddress)

	err := wsmanMessage.SetupWsmanClient("admin", cmd.Password, ctx.LocalTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
	if err != nil {
		return err
	}

	// Execute deactivation operation
	if cmd.PartialUnprovision {
		return cmd.executePartialUnprovision(wsmanMessage)
	}

	return cmd.executeFullUnprovision(wsmanMessage)
}

// executePartialUnprovision performs partial unprovision operation
func (cmd *DeactivateCmd) executePartialUnprovision(wsmanMessage *localamt.GoWSMANMessages) error {
	_, err := wsmanMessage.PartialUnprovision()
	if err != nil {
		log.Error("Status: Unable to partially deactivate ", err)

		return utils.UnableToDeactivate
	}

	log.Info("Status: Device partially deactivated")

	return nil
}

// executeFullUnprovision performs full unprovision operation
func (cmd *DeactivateCmd) executeFullUnprovision(wsmanMessage *localamt.GoWSMANMessages) error {
	_, err := wsmanMessage.Unprovision(1)
	if err != nil {
		log.Error("Status: Unable to deactivate ", err)

		return utils.UnableToDeactivate
	}

	log.Info("Status: Device deactivated")

	return nil
}

// deactivateCCM handles CCM mode deactivation
func (cmd *DeactivateCmd) deactivateCCM(ctx *Context) error {
	if cmd.Password != "" {
		log.Warn("Password not required for CCM deactivation")
	}

	status, err := ctx.AMTCommand.Unprovision()
	if err != nil || status != 0 {
		log.Error("Status: Failed to deactivate ", err)

		return utils.DeactivationFailed
	}

	log.Info("Status: Device deactivated")

	return nil
}
