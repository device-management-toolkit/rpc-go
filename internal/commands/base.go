/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// PasswordRequirer interface to be implemented by commands that conditionally require passwords
type PasswordRequirer interface {
	RequiresAMTPassword() bool
}

// AMTBaseCmd provides common AMT password and WSMAN client functionality
// for all commands that require AMT connectivity. This reduces code duplication
// and ensures consistent password handling across all commands.
type AMTBaseCmd struct {
	WSMan            interfaces.WSMANer `kong:"-"`
	Password         string             `help:"AMT password" env:"AMT_PASSWORD" name:"password" short:"p"`
	ControlMode      int                `kong:"-"` // Store the control mode for use by embedding commands
	LocalTLSEnforced bool               `kong:"-"`
}

// Validate implements Kong's Validate interface for centralized password validation.
// This method will be called automatically by Kong for any command that embeds AMTBaseCmd.
func (cmd *AMTBaseCmd) Validate() error {
	// Note: This base validation is intentionally minimal.
	// Password validation should be handled by the embedding command's ValidatePasswordIfNeeded method
	// when the command actually needs to use AMT functionality.
	return nil
}

// ValidatePasswordIfNeeded prompts for password if required and not already provided
func (cmd *AMTBaseCmd) ValidatePasswordIfNeeded(requirer PasswordRequirer) error {
	if !requirer.RequiresAMTPassword() {
		return nil
	}

	if cmd.Password == "" {
		fmt.Print("AMT Password: ")

		password, err := utils.PR.ReadPassword()
		if err != nil {
			return fmt.Errorf("failed to read AMT password: %w", err)
		}

		cmd.Password = password
	}

	return nil
}

// AfterApply sets up WSMAN client after validation.
// This method will be called automatically by Kong after command validation.
// The AMT command is injected via Kong's dependency injection system.
func (cmd *AMTBaseCmd) AfterApply(amtCommand amt.Interface) error {
	// Initialize WSMAN client if not already set up
	if cmd.WSMan == nil {
		// Check if TLS is Mandatory for LMS connection
		resp, _ := amtCommand.GetChangeEnabled()
		if resp.IsTlsEnforcedOnLocalPorts() {
			cmd.LocalTLSEnforced = true

			log.Trace("TLS is enforced on local ports")
		}

		// Get the current control mode using the injected AMT command
		controlMode, err := amtCommand.GetControlMode()
		if err != nil {
			log.Error("Failed to get control mode: ", err)

			return fmt.Errorf("failed to get control mode: %w", err)
		}

		cmd.ControlMode = controlMode

		cmd.WSMan = localamt.NewGoWSMANMessages(utils.LMSAddress)

		// Use the centralized TLS config with proper certificate validation
		tlsConfig := certs.GetTLSConfig(&cmd.ControlMode, nil, true)

		err = cmd.WSMan.SetupWsmanClient("admin", cmd.Password, cmd.LocalTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
		if err != nil {
			log.Error("Failed to setup WSMAN client: ", err)

			return err
		}
	}

	return nil
}

// GetPassword returns the AMT password, ensuring it's available
func (cmd *AMTBaseCmd) GetPassword() string {
	return cmd.Password
}

// GetWSManClient returns the WSMAN client instance
func (cmd *AMTBaseCmd) GetWSManClient() interfaces.WSMANer {
	return cmd.WSMan
}

// GetControlMode returns the AMT control mode
func (cmd *AMTBaseCmd) GetControlMode() int {
	return cmd.ControlMode
}

// RequiresAMTPassword indicates whether this command requires AMT password.
// This can be overridden by embedding commands if they have conditional requirements.
func (cmd *AMTBaseCmd) RequiresAMTPassword() bool {
	return true
}
