/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package diagnostics

import (
	"errors"
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	internaldiag "github.com/device-management-toolkit/rpc-go/v2/internal/commands/diagnostics"
)

// defaultFormat is the CLI's default for --format.
const defaultFormat = "json"

// ErrClassFetchFailed is matched (use errors.Is) by the error WSMAN returns
// together with its result when one or more classes could not be read.
var ErrClassFetchFailed = errors.New("WSMAN class fetch failed")

// errInvalidFormat repeats the CLI parser's check of --format.
var errInvalidFormat = errors.New(`--format must be one of "json","xml","table"`)

// WSMANClassesOptions configures WSMANClasses. It has no fields yet; it
// exists so that options can be added without breaking callers.
type WSMANClassesOptions struct{}

// WSMANClasses returns the names of the WSMAN classes WSMAN can read, sorted,
// as `rpc diagnostics wsman list` prints them. It does not access AMT.
func WSMANClasses(WSMANClassesOptions) []string {
	return internaldiag.SupportedWSMANClasses()
}

// WSMANOptions selects the classes WSMAN reads. Set All, or list Classes;
// setting both, or neither, is rejected with the CLI's messages.
type WSMANOptions struct {
	// Classes lists the WSMAN classes to read, by the names WSMANClasses
	// returns. Duplicates and blank names are dropped; an unknown name is
	// rejected. Must be empty when All is set.
	Classes []string
	// All reads every class WSMANClasses returns.
	All bool
	// Format is the format of WSMANResult.Output: "json", "xml" or "table".
	// If empty, "json" is used, as in the CLI.
	Format string
	// AMTPassword is the AMT admin password WSMAN authenticates with. If
	// empty, the AMT Local System Account is read over HECI and used instead;
	// WSMAN never prompts.
	AMTPassword string
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool
}

// WSMANClass is one WSMAN class read by WSMAN: Data holds the
// go-wsman-messages response for Class, or Err says why it could not be read.
type WSMANClass = internaldiag.WSMANClassData

// WSMANResult holds the WSMAN classes read by WSMAN.
type WSMANResult struct {
	// Classes holds every selected class, in the order WSMAN read them, each
	// with its data or its error.
	Classes []WSMANClass
	// Output is Classes rendered in WSMANOptions.Format, the bytes
	// `rpc diagnostics wsman get` writes; a class that could not be read is
	// rendered as a fetch_failed entry.
	Output []byte
}

// WSMAN reads WSMAN classes from AMT, as `rpc diagnostics wsman get` does,
// and returns them instead of writing them. Invalid options are rejected
// with the CLI's messages before AMT is accessed.
//
// When some classes cannot be read, WSMAN returns the result, with each
// failure in its WSMANClass.Err, together with an error matching
// ErrClassFetchFailed (use errors.Is). Unlike the CLI, it does so even when a
// single class was selected. If the classes were read but could not be
// rendered in opts.Format, the result comes with that error and its Output
// is incomplete. Any other error comes with a nil result.
// Requires elevated privileges (admin/root) to access the HECI driver.
func WSMAN(opts WSMANOptions) (*WSMANResult, error) {
	if opts.Format != "" && opts.Format != "json" && opts.Format != "xml" && opts.Format != "table" {
		return nil, fmt.Errorf("%w but got %q", errInvalidFormat, opts.Format)
	}

	cmd, ctx := newWSMANCommand(opts)

	// The command checks the classes only in Run, after AMT access.
	if _, err := cmd.ResolveClasses(); err != nil {
		return nil, err
	}

	if err := prepare(cmd, ctx); err != nil {
		return nil, err
	}

	classes, err := cmd.Fetch(ctx)

	return newWSMANResult(classes, err, cmd.Format)
}

// newWSMANCommand builds the wsman get command and its context from opts.
func newWSMANCommand(opts WSMANOptions) (*internaldiag.WSManGetCmd, *commands.Context) {
	format := opts.Format
	if format == "" {
		format = defaultFormat
	}

	cmd := &internaldiag.WSManGetCmd{
		Class:  opts.Classes,
		All:    opts.All,
		Format: format,
	}

	ctx := &commands.Context{
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
	}

	return cmd, ctx
}

// newWSMANResult builds WSMAN's result from what Fetch returned: no classes
// means nothing was read, and fetchErr is returned alone; classes with
// fetchErr means some could not be read.
func newWSMANResult(classes []WSMANClass, fetchErr error, format string) (*WSMANResult, error) {
	if classes == nil {
		return nil, fetchErr
	}

	output, renderErr := internaldiag.RenderWSMANClasses(classes, format)
	result := &WSMANResult{Classes: classes, Output: output}

	if fetchErr != nil {
		return result, fmt.Errorf("%w: %w", ErrClassFetchFailed, fetchErr)
	}

	return result, renderErr
}
