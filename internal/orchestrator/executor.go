/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"context"
	"os"
	"os/exec"
)

// CommandExecutor interface for executing commands
type CommandExecutor interface {
	Execute(args []string) error
}

// CLIExecutor executes commands using the CLI
type CLIExecutor struct{}

// Execute runs the RPC command with the given arguments
func (e *CLIExecutor) Execute(args []string) error {
	// Get the current executable path
	executable, err := os.Executable()
	if err != nil {
		// Fallback to "rpc" if we can't determine the executable
		executable = "rpc"
	}

	// Replace the first "rpc" argument with the actual executable
	if len(args) > 0 && args[0] == "rpc" {
		args = args[1:]
	}

	// Create the command with a context so it can be canceled by parent callers in the future.
	// Using context.Background() here because the existing interface does not yet expose a context;
	// if/when a higher-level context is added we can thread it through without further linter changes.
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Run the command
	return cmd.Run()
}

// DirectExecutor executes commands directly (for testing or embedded use)
type DirectExecutor struct {
	ExecuteFunc func(args []string) error
}

// Execute runs the command using the provided function
func (e *DirectExecutor) Execute(args []string) error {
	if e.ExecuteFunc != nil {
		return e.ExecuteFunc(args)
	}

	return nil
}
