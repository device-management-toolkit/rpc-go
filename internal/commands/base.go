/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"crypto/tls"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
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
	ControlMode      int                `kong:"-"` // Store the control mode for use by embedding commands
	LocalTLSEnforced bool               `kong:"-"`
	HECIAvailable    bool               `kong:"-"` // Whether HECI/MEI driver is accessible
	// SkipWSMANSetup allows embedding commands (e.g., amtinfo without --userCert)
	// to bypass LMS/WSMAN client initialization when it isn't required.
	SkipWSMANSetup bool `kong:"-"`
	// afterApplied ensures AfterApply runs its heavy init exactly once.
	afterApplied bool `kong:"-"`
}

// EnsureAMTPassword prompts for an AMT password when required and ctx.AMTPassword is empty.
// For non-activated devices (control mode 0), it also prompts for password confirmation to prevent typos.
func (cmd *AMTBaseCmd) EnsureAMTPassword(ctx *Context, requirer PasswordRequirer) error {
	if !requirer.RequiresAMTPassword() {
		return nil
	}

	if strings.TrimSpace(ctx.AMTPassword) != "" {
		return nil // Password already provided, no prompting
	}

	var pw string

	var err error

	// If device not activated (control mode 0), require confirmation
	if cmd.ControlMode == 0 {
		pw, err = utils.PR.ReadPasswordWithConfirmation("AMT Password: ", "Confirm AMT Password: ")
	} else {
		fmt.Print("AMT Password: ")

		pw, err = utils.PR.ReadPassword()

		fmt.Println()
	}

	if err != nil {
		return fmt.Errorf("failed to read AMT password: %w", err)
	}

	if pw == "" {
		return fmt.Errorf("password cannot be empty")
	}

	ctx.AMTPassword = pw

	return nil
}

// EnsureWSMAN sets up the WSMAN client lazily if not already created and a password is available.
// amtTLSConfig builds the TLS config for the local AMT connection.
func (cmd *AMTBaseCmd) amtTLSConfig(ctx *Context) *tls.Config {
	return certs.GetTLSConfig(&cmd.ControlMode, nil, ctx.SkipAMTCertCheck, nil)
}

func (cmd *AMTBaseCmd) EnsureWSMAN(ctx *Context) error {
	if cmd.WSMan != nil {
		return nil
	}

	if strings.TrimSpace(ctx.AMTPassword) == "" {
		log.Debug("WSMAN client not created: AMT password not yet available")

		return nil
	}

	cmd.WSMan = localamt.NewGoWSMANMessages(utils.LMSAddress)

	if err := cmd.WSMan.SetupWsmanClient("admin", ctx.AMTPassword, cmd.LocalTLSEnforced, log.GetLevel() == log.TraceLevel, cmd.amtTLSConfig(ctx)); err != nil {
		return fmt.Errorf("failed to setup WSMAN client: %w", err)
	}

	return nil
}

// AfterApply sets up WSMAN client after validation.
// This method will be called automatically by Kong after command validation.
// The AMT command is injected via Kong's dependency injection system.
func (cmd *AMTBaseCmd) AfterApply(amtCommand amt.Interface) error {
	return cmd.afterApply(amtCommand, utils.IsElevated(), runtime.GOARCH, time.Sleep)
}

func (cmd *AMTBaseCmd) afterApply(amtCommand amt.Interface, elevated bool, arch string, sleep func(time.Duration)) error {
	if cmd.afterApplied {
		// Idempotent: avoid duplicate work/logging if Kong calls AfterApply twice.
		return nil
	}

	log.Trace("Running AfterApply for AMTBaseCmd")

	// Ensure we close the MEI device connection after getting control mode and TLS status
	defer amtCommand.Close()

	if !isAMTCapableArchitecture(arch) {
		cmd.ControlMode = -1
		if cmd.SkipWSMANSetup {
			cmd.afterApplied = true

			return nil
		}

		return utils.HECIDriverNotDetected
	}

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

	// HECI requires admin — fail fast when not elevated instead of retrying.
	if !elevated {
		if cmd.SkipWSMANSetup {
			// amtinfo: degrade gracefully, show OS-level data only
			cmd.ControlMode = -1
			cmd.afterApplied = true

			return nil
		}

		if _, err := amtCommand.GetControlMode(); err != nil && isPermanentHECIError(err) {
			log.Debugf("HECI permanently unavailable while unprivileged: %v", err)

			cmd.ControlMode = -1

			return classifyHECIFailure(err)
		}

		return utils.IncorrectPermissions
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		controlMode, err = amtCommand.GetControlMode()
		if err == nil {
			break
		}

		// Permanent hardware-absence errors — no point retrying (e.g. non-vPro device)
		if isPermanentHECIError(err) {
			log.Debugf("HECI permanently unavailable: %v", err)

			break
		}

		if attempt < maxAttempts {
			log.Warnf("GetControlMode failed (attempt %d/%d): %v. Retrying in %s...", attempt, maxAttempts, err, backoff)
			sleep(backoff)

			continue
		}
	}

	if err != nil {
		// For commands that tolerate missing HECI (e.g. amtinfo), degrade gracefully
		if cmd.SkipWSMANSetup {
			log.Debugf("HECI not available, AMT data will be limited: %v", err)

			cmd.ControlMode = -1
			cmd.afterApplied = true

			return nil
		}

		return classifyHECIFailure(err)
	}

	cmd.ControlMode = controlMode
	cmd.HECIAvailable = true
	log.Tracef("AMTBaseCmd detected control mode: %d", cmd.ControlMode)

	// Determine if TLS is enforced on local ports; needed even if we skip full WSMAN setup
	resp, _ := amtCommand.GetChangeEnabled()
	if resp.IsTlsEnforcedOnLocalPorts() {
		cmd.LocalTLSEnforced = true

		log.Info("TLS is enforced on local ports")
	} else {
		log.Trace("TLS is not enforced on local ports")
	}

	log.Tracef("AMTBaseCmd setup complete: controlMode=%d localTLSEnforced=%t", cmd.ControlMode, cmd.LocalTLSEnforced)

	cmd.afterApplied = true

	return nil
}

func isAMTCapableArchitecture(arch string) bool {
	switch arch {
	case "amd64", "386":
		return true
	default:
		return false
	}
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

// isPermanentHECIError returns true when retrying a HECI probe is not expected to help.
func isPermanentHECIError(err error) bool {
	return errors.Is(err, heci.ErrDeviceNotFound) ||
		errors.Is(err, heci.ErrUnsupportedDevice) ||
		errors.Is(err, heci.ErrPermissionDenied) ||
		errors.Is(err, utils.HECIDriverNotDetected)
}

// classifyHECIFailure maps a probe failure to its RPC exit code and preserves the cause.
func classifyHECIFailure(err error) error {
	switch {
	case errors.Is(err, heci.ErrPermissionDenied):
		log.Error("Permission denied accessing the MEI/HECI device. " +
			"Run with administrator or root privileges.")

		return fmt.Errorf("%w: %w", utils.IncorrectPermissions, err)
	case errors.Is(err, heci.ErrUnsupportedDevice):
		log.Error("The MEI device on this system does not expose the AMT (PTHI) client. " +
			"This is typically non-vPro hardware.")

		return fmt.Errorf("%w: %w", utils.AmtNotDetected, err)
	default:
		log.Error("Failed to execute due to access issues. " +
			"Please ensure that Intel ME is present, " +
			"the MEI driver is installed, " +
			"and the runtime has administrator or root privileges.")

		return fmt.Errorf("%w: %w", utils.HECIDriverNotDetected, err)
	}
}
