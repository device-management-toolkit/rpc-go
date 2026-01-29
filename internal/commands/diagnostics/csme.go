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
	log "github.com/sirupsen/logrus"
)

// CSMECmd dumps CSME / firmware flash diagnostics.
type CSMECmd struct {
	DiagnosticsBaseCmd

	Flog FlogCmd `cmd:"flog" help:"Retrieve the CSME Flash Log (FLOG) and save it to a file"`
}

// FlogCmd represents the flog subcommand
type FlogCmd struct {
	DiagnosticsBaseCmd

	Output string `help:"Output file path for the FLOG binary data" short:"o" required:""`
}

// Run executes the CSME diagnostics command (parent command - shows help).
func (cmd *CSMECmd) Run(ctx *commands.Context) error {
	return nil
}

// Run executes the flog command
func (cmd *FlogCmd) Run(ctx *commands.Context) error {
	log.Debug("Starting FLOG retrieval")

	// Retrieve the FLOG data
	flogData, err := ctx.AMTCommand.GetFlog()
	if err != nil {
		return fmt.Errorf("failed to retrieve FLOG: %w", err)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(cmd.Output)
	if outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Write the binary FLOG data to file
	if err := os.WriteFile(cmd.Output, flogData, 0o644); err != nil {
		return fmt.Errorf("failed to write FLOG file: %w", err)
	}

	fmt.Printf("CSME Flash Log (FLOG) successfully retrieved\n")
	fmt.Printf("Output file: %s\n", cmd.Output)
	fmt.Printf("Size: %d bytes\n", len(flogData))
	log.Infof("FLOG data saved to: %s", cmd.Output)

	return nil
}
