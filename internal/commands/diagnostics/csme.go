/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	log "github.com/sirupsen/logrus"
)

// CSMECmd dumps CSME / firmware flash diagnostics.
type CSMECmd struct {
	DiagnosticsBaseCmd

	Output string `help:"Output file path for the flash log binary data" short:"o"`
}

// Run executes the top-level "csme" diagnostics command, retrieving the CSME flash log (FLOG).
func (cmd *CSMECmd) Run(ctx *commands.Context) error {
	log.Debug("Starting flash log retrieval")

	// Generate default filename if not provided
	if cmd.Output == "" {
		timestamp := time.Now().Format("20060102_150405")
		cmd.Output = fmt.Sprintf("%s_csme_flash_log.bin", timestamp)
	}

	// Retrieve the FLOG data
	flogData, err := ctx.AMTCommand.GetFlog()
	if err != nil {
		return fmt.Errorf("failed to retrieve flash log: %w", err)
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
		return fmt.Errorf("failed to write flash log file: %w", err)
	}

	fmt.Printf("CSME Flash Log (FLOG) successfully retrieved\n")
	fmt.Printf("Output file: %s\n", cmd.Output)
	fmt.Printf("Size: %d bytes\n", len(flogData))
	log.Debugf("FLOG data saved to: %s", cmd.Output)

	return nil
}
