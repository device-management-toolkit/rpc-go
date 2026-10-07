/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Exit codes from rpc-go's pkg/utils that deserve a hint for the agent / operator.
var exitCodeHints = map[int]string{
	1:   "rpc needs administrator/root privileges: run the MCP server elevated",
	2:   "the Intel MEI/HECI driver was not detected on this device",
	3:   "Intel AMT was not detected on this device",
	23:  "the AMT password is missing or incorrect: set AMT_PASSWORD for the MCP server",
	100: "AMT rejected the credentials: check AMT_PASSWORD",
	115: "AMT is not activated on this device",
}

// RPCError is returned when the rpc process exits with a non-zero code.
type RPCError struct {
	ExitCode int
	Message  string
}

func (e *RPCError) Error() string {
	msg := fmt.Sprintf("rpc exited with code %d: %s", e.ExitCode, e.Message)

	// rpc exits with GenericFailure (10) when Kong wraps a typed error, but the logged
	// message still starts with "Error <code>:", so prefer that code for the hint.
	code := e.ExitCode

	var logged int
	if _, err := fmt.Sscanf(e.Message, "Error %d:", &logged); err == nil {
		code = logged
	}

	if hint, ok := exitCodeHints[code]; ok {
		msg += " (hint: " + hint + ")"
	}

	return msg
}

// execFunc runs a process and returns its stdout, stderr and exit code. It is replaced in tests.
type execFunc func(ctx context.Context, name string, args, env []string) (stdout, stderr []byte, exitCode int, err error)

// Runner invokes the rpc binary. It never passes secrets on the command line: rpc
// inherits this server's environment and reads AMT_PASSWORD (and the Console
// AUTH_* variables) from it.
type Runner struct {
	RPCPath string
	exec    execFunc
}

// NewRunner creates a Runner that executes the rpc binary at rpcPath.
func NewRunner(rpcPath string) *Runner {
	return &Runner{RPCPath: rpcPath, exec: runProcess}
}

// Run executes `rpc <args...> --json` and returns its JSON stdout.
func (r *Runner) Run(ctx context.Context, timeout time.Duration, args ...string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args = append(args, "--json")

	stdout, stderr, exitCode, err := r.exec(ctx, r.RPCPath, args, os.Environ())
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("rpc %s timed out after %s", strings.Join(args, " "), timeout)
		}

		return nil, fmt.Errorf("failed to run rpc: %w", err)
	}

	if exitCode != 0 {
		return nil, &RPCError{ExitCode: exitCode, Message: errorMessage(stderr)}
	}

	return toJSON(stdout), nil
}

// toJSON returns stdout when it is a JSON object, otherwise wraps the text so the
// tool result is always a JSON object.
func toJSON(stdout []byte) json.RawMessage {
	trimmed := bytes.TrimSpace(stdout)
	if len(trimmed) > 0 && trimmed[0] == '{' && json.Valid(trimmed) {
		return trimmed
	}

	wrapped, _ := json.Marshal(map[string]string{"output": string(trimmed)})

	return wrapped
}

// errorMessage extracts the last error message from rpc's stderr. With --json rpc logs
// one JSON object per line ({"level":"error","msg":"..."}); fall back to the raw text.
func errorMessage(stderr []byte) string {
	var last string

	scanner := bufio.NewScanner(bytes.NewReader(stderr))
	for scanner.Scan() {
		var entry struct {
			Level string `json:"level"`
			Msg   string `json:"msg"`
		}

		if json.Unmarshal(scanner.Bytes(), &entry) == nil && (entry.Level == "error" || entry.Level == "fatal") {
			last = entry.Msg
		}
	}

	if last != "" {
		return last
	}

	const maxLen = 2000

	text := strings.TrimSpace(string(stderr))
	if len(text) > maxLen {
		text = text[len(text)-maxLen:]
	}

	if text == "" {
		return "no error output"
	}

	return text
}

func runProcess(ctx context.Context, name string, args, env []string) (stdout, stderr []byte, exitCode int, err error) {
	var outBuf, errBuf bytes.Buffer

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	// No stdin: rpc must never block on an interactive prompt (password, self-elevation).
	cmd.Stdin = nil

	err = cmd.Run()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		return outBuf.Bytes(), errBuf.Bytes(), exitErr.ExitCode(), nil
	}

	return outBuf.Bytes(), errBuf.Bytes(), 0, err
}
