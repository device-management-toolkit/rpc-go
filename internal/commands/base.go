/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"fmt"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
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
	// SkipWSMANSetup allows embedding commands (e.g., amtinfo without --userCert)
	// to bypass LMS/WSMAN client initialization when it isn't required.
	SkipWSMANSetup bool `kong:"-"`
	// afterApplied ensures AfterApply runs its heavy init exactly once.
	afterApplied bool `kong:"-"`
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

		fmt.Println() // Add newline after password input

		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}

		cmd.Password = password
	}

	return nil
}

// AfterApply sets up WSMAN client after validation.
// This method will be called automatically by Kong after command validation.
// The AMT command is injected via Kong's dependency injection system.
func (cmd *AMTBaseCmd) AfterApply(amtCommand amt.Interface) error {
	if cmd.afterApplied {
		// Idempotent: avoid duplicate work/logging if Kong calls AfterApply twice.
		return nil
	}

	log.Trace("Running AfterApply for AMTBaseCmd")
	// always have the control mode handy
	// Get the current control mode using the injected AMT command, with retries if AMT is busy
	var (
		controlMode int
		err         error
	)

	const (
		maxAttempts = 4
		backoff     = 4 * time.Second
	)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		controlMode, err = amtCommand.GetControlMode()
		if err == nil {
			break
		}

		if attempt < maxAttempts {
			log.Warnf("GetControlMode failed (attempt %d/%d): %v. Retrying in %s...", attempt, maxAttempts, err, backoff)
			time.Sleep(backoff)

			continue
		}

		log.Error("Failed to get control mode: ", err)

		return fmt.Errorf("failed to get control mode: %w", err)
	}

	cmd.ControlMode = controlMode

	// Determine if TLS is enforced on local ports; needed even if we skip full WSMAN setup
	resp, _ := amtCommand.GetChangeEnabled()
	if resp.IsTlsEnforcedOnLocalPorts() {
		cmd.LocalTLSEnforced = true

		log.Trace("TLS is enforced on local ports")
	}

	// Some commands (like amtinfo) can lazily set up LMS/WSMAN later.
	if cmd.SkipWSMANSetup {
		cmd.afterApplied = true

		return nil
	}

	log.Trace("Getting control mode and setting up WSMAN client if needed")

	// Initialize WSMAN client if not already set up
	if cmd.WSMan == nil {
		// Cannot set up WSMAN without AMT password
		if cmd.Password == "" {
			log.Debug("Skipping WSMAN setup: AMT password not provided yet")

			cmd.afterApplied = true

			return nil
		}

		log.Trace("Setting up WSMAN client")

		cmd.WSMan = localamt.NewGoWSMANMessages(utils.LMSAddress)

		// Use the centralized TLS config with proper certificate validation
		tlsConfig := certs.GetTLSConfig(&cmd.ControlMode, nil, true)

		err = cmd.WSMan.SetupWsmanClient("admin", cmd.Password, cmd.LocalTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
		if err != nil {
			log.Error("Failed to setup WSMAN client: ", err)

			return err
		}
	}

	cmd.afterApplied = true

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
