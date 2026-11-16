/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package diagnostics provides a public API for the firmware diagnostics of
// the local device: what the rpc diagnostics subcommands write to files or
// stdout, returned as data.
//
// CIRA reads the CIRA log, CSME reads the CSME flash log, WSMANClasses lists
// the WSMAN classes WSMAN can read, WSMAN reads them, and Bundle writes all
// of it to a zip file. Every function except WSMANClasses needs elevated
// privileges (admin/root) to access the HECI driver.
package diagnostics

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	internaldiag "github.com/device-management-toolkit/rpc-go/v2/internal/commands/diagnostics"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
)

// ErrCIRALogNotSupported is returned by CIRA when the firmware has no CIRA log.
var ErrCIRALogNotSupported = internaldiag.ErrCIRALogNotSupported

// afterApplier is a diagnostics command's Kong hook that reads AMT's state.
type afterApplier interface {
	AfterApply(amt.Interface) error
}

// prepare calls the hook Kong calls before Run: the diagnostics commands
// have no BeforeApply or Validate, and none uses the CLI root's auth flags.
// AfterApply checks HECI access, reads the control mode and closes HECI
// again; prepare then hands ctx the AMT command, which opens and closes HECI
// on each call.
func prepare(cmd afterApplier, ctx *commands.Context) error {
	amtCommand := amt.NewAMTCommand()

	if err := cmd.AfterApply(&amtCommand); err != nil {
		return err
	}

	ctx.AMTCommand = &amtCommand

	return nil
}

// CIRALog is the CIRA log AMT keeps: the current CIRA connection status, the
// last failed tunnel and the last failed connection attempt.
type CIRALog = pthi.GetCiraLogResponse

// CIRAResult is the CIRA log read by CIRA.
type CIRAResult struct {
	// Log is the parsed CIRA log.
	Log CIRALog
	// Text is Log rendered as the text `rpc diagnostics cira` writes to its
	// output file.
	Text string
}

// CIRAOptions configures CIRA. It has no fields yet; it exists so that
// options can be added without breaking callers.
type CIRAOptions struct{}

// CIRA reads the CIRA log from the firmware, as `rpc diagnostics cira` does,
// and returns it instead of writing it to a file. It needs no AMT password
// and never prompts. It returns ErrCIRALogNotSupported when the firmware has
// no CIRA log.
// Requires elevated privileges (admin/root) to access the HECI driver.
func CIRA(opts CIRAOptions) (*CIRAResult, error) {
	cmd, ctx := newCIRACommand(opts)

	if err := prepare(cmd, ctx); err != nil {
		return nil, err
	}

	log, err := cmd.Collect(ctx)
	if err != nil {
		return nil, err
	}

	return newCIRAResult(log)
}

// newCIRAResult pairs the CIRA log with the text the CLI writes for it.
func newCIRAResult(log CIRALog) (*CIRAResult, error) {
	text, err := internaldiag.CIRALogText(log)

	return &CIRAResult{Log: log, Text: text}, err
}

// newCIRACommand builds the cira command and its context. CIRAOptions has no
// fields to map yet.
func newCIRACommand(CIRAOptions) (*internaldiag.CIRACmd, *commands.Context) {
	return &internaldiag.CIRACmd{}, &commands.Context{}
}

// CSMEOptions configures CSME. It has no fields yet; it exists so that
// options can be added without breaking callers.
type CSMEOptions struct{}

// CSME reads the CSME flash log (FLOG) from the firmware, as
// `rpc diagnostics csme` does, and returns the bytes the CLI writes to its
// output file. It needs no AMT password and never prompts.
// Requires elevated privileges (admin/root) to access the HECI driver.
func CSME(opts CSMEOptions) ([]byte, error) {
	cmd, ctx := newCSMECommand(opts)

	if err := prepare(cmd, ctx); err != nil {
		return nil, err
	}

	return cmd.Collect(ctx)
}

// newCSMECommand builds the csme command and its context. CSMEOptions has no
// fields to map yet.
func newCSMECommand(CSMEOptions) (*internaldiag.CSMECmd, *commands.Context) {
	return &internaldiag.CSMECmd{}, &commands.Context{}
}
