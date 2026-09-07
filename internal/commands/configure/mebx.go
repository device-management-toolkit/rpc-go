/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// MEBxCmd represents the MEBx password configuration command
type MEBxCmd struct {
	ConfigureBaseCmd

	// MEBx password
	MEBxPassword string `help:"MEBx password" env:"MEBX_PASSWORD" name:"mebxpassword"`
}

// AfterApply prints a security warning if the MEBx password was passed via CLI flag.
func (cmd *MEBxCmd) AfterApply(amtCommand amt.Interface) error {
	if err := cmd.AMTBaseCmd.AfterApply(amtCommand); err != nil {
		return err
	}

	commands.WarnIfCredentialsOnCLI(commands.CredentialCLI{Value: cmd.MEBxPassword, EnvVar: "MEBX_PASSWORD", FlagName: []string{"mebxpassword"}})

	return nil
}

// Validate implements Kong's Validate interface for MEBx command validation
func (cmd *MEBxCmd) Validate() error {
	// First call the base Validate to handle password validation
	if err := cmd.ConfigureBaseCmd.Validate(); err != nil {
		return err
	}

	// Validate MEBx password - prompt if not provided
	if cmd.MEBxPassword == "" {
		fmt.Print("\nNew MEBx Password: ")

		password, err := utils.PR.ReadPassword()
		if err != nil {
			return fmt.Errorf("failed to read MEBx password: %w", err)
		}

		cmd.MEBxPassword = password
	}

	return nil
}

// Run executes the MEBx configuration command
func (cmd *MEBxCmd) Run(ctx *commands.Context) error {
	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}

	log.Info("Configuring MEBx password...")

	// Get control mode for validation
	controlMode := cmd.GetControlMode()

	// Validate that device is in ACM (control mode 2)
	if controlMode != 2 {
		errMsg := fmt.Sprintf("MEBx password can only be configured in ACM. Current device control mode: %s",
			utils.InterpretControlMode(controlMode))
		log.Error(errMsg)

		return utils.SetMEBXPasswordFailed
	}

	if controlMode != 2 { // If not in ACM, return an error.
		errMsg := "MEBx password can only be configured in ACM. Current device control mode: " + utils.InterpretControlMode(controlMode)
		log.Error(errMsg)

		return utils.SetMEBXPasswordFailed
	}

	// Set up MEBx with the provided password.
	response, err := cmd.WSMan.SetupMEBX(cmd.MEBxPassword)
	log.Trace(response)

	if err != nil {
		log.Error("Failed to configure MEBx Password:", err)

		return err
	}

	log.Info("Successfully configured MEBx Password.")

	return nil
}
