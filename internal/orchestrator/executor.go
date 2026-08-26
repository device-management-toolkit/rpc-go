/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

const rpcExecutableName = "rpc"

// ExecError carries subprocess exit code + output; match on ExitCode, not Output substrings.
type ExecError struct {
	ExitCode int
	Output   string
	Err      error
}

func (e *ExecError) Error() string {
	if e == nil {
		return ""
	}

	if e.Output == "" {
		return e.Err.Error()
	}

	return fmt.Sprintf("%v: %s", e.Err, e.Output)
}

func (e *ExecError) Unwrap() error { return e.Err }

// CommandExecutor interface for executing commands
type CommandExecutor interface {
	// Execute runs a command with optional custom environment variables (env may be nil)
	// without mutating the global process environment.
	Execute(args []string, env map[string]string) error
}

// CLIExecutor executes commands using the CLI
type CLIExecutor struct{}

// Execute runs the RPC command with the given arguments and optional custom environment variables.
// Environment variables are passed per-subprocess without mutating the global process environment.
func (e *CLIExecutor) Execute(args []string, env map[string]string) error {
	// Get the current executable path
	executable, err := os.Executable()
	if err != nil {
		// Fallback to "rpc" if we can't determine the executable
		executable = rpcExecutableName
	}

	// Replace the first "rpc" argument with the actual executable
	if len(args) > 0 && args[0] == rpcExecutableName {
		args = args[1:]
	}

	// Create the command with a context so it can be canceled by parent callers in the future.
	// Using context.Background() here because the existing interface does not yet expose a context;
	// if/when a higher-level context is added we can thread it through without further linter changes.
	ctx := context.Background()

	cmd := exec.CommandContext(ctx, executable, args...)

	// Keep only the environment needed by the subprocess. PATH is required by
	// commands invoked by the RPC binary; credentials and other configuration
	// are supplied explicitly by the orchestrator.
	if _, provided := env["PATH"]; !provided {
		path, ok := os.LookupEnv("PATH")
		if !ok {
			path = ""
		}

		cmd.Env = append(cmd.Env, "PATH="+path)
	}

	// Do not mutate the global process environment when passing per-subprocess values.
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Capture output while still streaming to the console
	var buf bytes.Buffer

	cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
	cmd.Stdin = os.Stdin

	// Run the command
	err = cmd.Run()
	if err != nil {
		ee := &ExecError{Err: err, Output: buf.String()}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			ee.ExitCode = exitErr.ExitCode()
		}

		return ee
	}

	return nil
}

// DirectExecutor executes commands directly (for testing or embedded use)
type DirectExecutor struct {
	ExecuteFunc func(args []string, env map[string]string) error
}

// Execute runs the command using the provided function
func (e *DirectExecutor) Execute(args []string, env map[string]string) error {
	if e.ExecuteFunc != nil {
		return e.ExecuteFunc(args, env)
	}

	return nil
}
