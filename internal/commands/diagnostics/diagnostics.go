/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
)

// ensureParentDir creates the directory that will contain path, if any.
func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	return nil
}

// DiagnosticsBaseCmd provides base functionality for all diagnostics commands.
type DiagnosticsBaseCmd struct {
	commands.AMTBaseCmd

	// quiet suppresses success output for temp files the bundle archives and removes.
	quiet bool `kong:"-"`
}

// DiagnosticsCmd is the main diagnostics command that contains all subcommands.
type DiagnosticsCmd struct {
	CIRA   CIRACmd   `cmd:"cira"   help:"Dump CIRA-related diagnostics"`
	CSME   CSMECmd   `cmd:"csme"   help:"Dump CSME / firmware flash diagnostics"`
	WSMan  WSManCmd  `cmd:"" name:"wsman" aliases:"ws-man" help:"Dump AMT WSMAN class(es)"`
	Bundle BundleCmd `cmd:"bundle" help:"Collect a full diagnostics bundle"`
}
