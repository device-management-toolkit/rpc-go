/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// DefaultSkipAMTCertCheck is set by CLI context to control AMT TLS verification at WSMAN setup time.
// It is used in AMTBaseCmd.AfterApply where the CLI context isn't directly accessible.
var DefaultSkipAMTCertCheck bool

// PasswordRequirer interface to be implemented by commands that conditionally require passwords
type PasswordRequirer interface {
	RequiresAMTPassword() bool
}

// AMTBaseCmd provides common AMT password and WSMAN client functionality
// for all commands that require AMT connectivity. This reduces code duplication
// and ensures consistent password handling across all commands.
type AMTBaseCmd struct {
	WSMan            interfaces.WSMANer `kong:"-"`
	ControlMode      int                `kong:"-"` // Store the control mode for use by embedding commands
	LocalTLSEnforced bool               `kong:"-"`
	// SkipWSMANSetup allows embedding commands (e.g., amtinfo without --userCert)
	// to bypass LMS/WSMAN client initialization when it isn't required.
	SkipWSMANSetup bool `kong:"-"`
	// afterApplied ensures AfterApply runs its heavy init exactly once.
	afterApplied bool `kong:"-"`
}

// ValidatePasswordIfNeeded prompts for password if required and not already provided
// EnsureAMTPassword prompts (once) if the command requires an AMT password and ctx.AMTPassword is empty.
func (cmd *AMTBaseCmd) EnsureAMTPassword(ctx *Context, requirer PasswordRequirer) error {
	if !requirer.RequiresAMTPassword() {
		return nil
	}

	if strings.TrimSpace(ctx.AMTPassword) != "" {
		return nil
	}

	fmt.Print("AMT Password: ")

	pw, err := utils.PR.ReadPassword()
	if err != nil {
		return fmt.Errorf("failed to read AMT password: %w", err)
	}

	fmt.Println()

	if pw == "" {
		return fmt.Errorf("password cannot be empty")
	}

	ctx.AMTPassword = pw

	return nil
}

// EnsureWSMAN sets up the WSMAN client lazily if not already created and a password is available.
func (cmd *AMTBaseCmd) EnsureWSMAN(ctx *Context) error {
	if cmd.WSMan != nil {
		return nil
	}

	if strings.TrimSpace(ctx.AMTPassword) == "" {
		log.Debug("WSMAN client not created: AMT password not yet available")

		return nil
	}

	cmd.WSMan = localamt.NewGoWSMANMessages(utils.LMSAddress)

	tlsConfig := certs.GetTLSConfig(&cmd.ControlMode, nil, true)
	if err := cmd.WSMan.SetupWsmanClient("admin", ctx.AMTPassword, cmd.LocalTLSEnforced, log.GetLevel() == log.TraceLevel, tlsConfig); err != nil {
		return fmt.Errorf("failed to setup WSMAN client: %w", err)
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

	// We no longer build WSMAN here. Control mode + TLS enforcement only.
	cmd.afterApplied = true

	return nil
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
