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

// ErrBundleIncomplete is matched (use errors.Is) by the error Bundle returns
// together with its result when the bundle was written but one or more
// collectors failed or were incomplete.
var ErrBundleIncomplete = errors.New("diagnostics bundle incomplete")

// BundleResult is what Bundle wrote: Path is the zip file, Manifest the
// manifest.json stored in it.
type BundleResult = internaldiag.BundleResult

// BundleManifest records when a bundle was created and how each collector
// fared; Incomplete counts the collectors that did not succeed.
type BundleManifest = internaldiag.BundleManifest

// BundleCollector is one collector's entry in a BundleManifest: cira
// (cira.txt), csme (csme_flash_log.bin) or wsman (wsman.json). Status is
// "success", "partial" (File is in the bundle but incomplete) or "failed"
// (no File); Error says why it did not succeed.
type BundleCollector = internaldiag.BundleCollectorResult

// BundleOptions configures Bundle.
type BundleOptions struct {
	// Output is the path of the zip file to write. ".zip" is appended when it
	// has no extension, and missing parent directories are created. If empty,
	// <YYYYMMDD_HHMMSS>_diagnostics_bundle.zip in the current directory is
	// used, as in the CLI. BundleResult.Path holds the path used.
	Output string
	// AMTPassword is the AMT admin password the wsman collector authenticates
	// with. If empty, the AMT Local System Account is read over HECI and used
	// instead; Bundle never prompts.
	AMTPassword string
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool
}

// Bundle collects the CIRA log, the CSME flash log and every WSMAN class, as
// `rpc diagnostics bundle` does, and writes them with a manifest.json to the
// zip file opts.Output names. It returns where it wrote the bundle and the
// manifest.
//
// When the bundle was written but some collectors failed or were incomplete,
// Bundle returns the result together with an error matching
// ErrBundleIncomplete (use errors.Is); this includes the case where no
// collector produced anything and the bundle holds only the manifest. Any
// other error comes with a nil result; a failure while writing the zip can
// leave a partial file at opts.Output.
// Requires elevated privileges (admin/root) to access the HECI driver.
func Bundle(opts BundleOptions) (*BundleResult, error) {
	cmd, ctx := newBundleCommand(opts)

	if err := prepare(cmd, ctx); err != nil {
		return nil, err
	}

	result, err := cmd.Collect(ctx)

	return result, bundleError(result, err)
}

// newBundleCommand builds the bundle command and its context from opts.
func newBundleCommand(opts BundleOptions) (*internaldiag.BundleCmd, *commands.Context) {
	cmd := &internaldiag.BundleCmd{Output: opts.Output}

	ctx := &commands.Context{
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
	}

	return cmd, ctx
}

// bundleError is the error Bundle returns with result: err alone when no
// bundle was written, otherwise ErrBundleIncomplete when a collector did not
// succeed, as the CLI warns after writing the bundle.
func bundleError(result *BundleResult, err error) error {
	if result == nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("%w: %w", ErrBundleIncomplete, err)
	}

	if failures := result.Manifest.Incomplete(); failures > 0 {
		return fmt.Errorf("%w: %d diagnostic collector(s) were incomplete; see manifest.json for details",
			ErrBundleIncomplete, failures)
	}

	return nil
}
