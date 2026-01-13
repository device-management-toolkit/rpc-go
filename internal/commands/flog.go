/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	log "github.com/sirupsen/logrus"
)

// FlogCmd represents the flog command with Kong CLI binding
type FlogCmd struct {
	AMTBaseCmd

	Output string `help:"Output file path for the FLOG binary data" short:"o" required:""`
}

// Run executes the flog command
func (cmd *FlogCmd) Run(kctx *kong.Context, amtCommand amt.Interface) error {
	log.Debug("Starting FLOG retrieval")

	// Retrieve the FLOG data
	flogData, err := amtCommand.GetFlog()
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
