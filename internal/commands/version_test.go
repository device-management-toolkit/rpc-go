/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCmd_Run_PlainText(t *testing.T) {
	tests := []struct {
		name        string
		jsonOutput  bool
		description string
	}{
		{
			name:        "plain text output",
			jsonOutput:  false,
			description: "should output version in plain text format",
		},
		{
			name:        "json output",
			jsonOutput:  true,
			description: "should output version in JSON format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			require.NoError(t, err)

			os.Stdout = w

			// Create command and context
			cmd := &VersionCmd{}
			ctx := &Context{
				JsonOutput: tt.jsonOutput,
			}

			// Run the command
			err = cmd.Run(ctx)
			assert.NoError(t, err)

			// Close writer and restore stdout
			w.Close()

			output, err := io.ReadAll(r)
			require.NoError(t, err)

			os.Stdout = oldStdout

			outputStr := string(output)

			if tt.jsonOutput {
				// Verify JSON output
				assert.True(t, json.Valid(output), "Output should be valid JSON")

				var info map[string]string

				err := json.Unmarshal(output, &info)
				assert.NoError(t, err)

				// Check required fields
				assert.Equal(t, strings.ToUpper(utils.ProjectName), info["app"])
				assert.Equal(t, utils.ProjectVersion, info["version"])
				assert.Equal(t, utils.ProtocolVersion, info["protocol"])

				// Verify structure
				assert.Len(t, info, 3, "JSON output should have exactly 3 fields")
			} else {
				// Verify plain text output
				lines := strings.Split(strings.TrimSpace(outputStr), "\n")
				assert.Len(t, lines, 3, "Plain text output should have exactly 3 lines")

				assert.Equal(t, strings.ToUpper(utils.ProjectName), lines[0])
				assert.Equal(t, "Version "+utils.ProjectVersion, lines[1])
				assert.Equal(t, "Protocol "+utils.ProtocolVersion, lines[2])
			}
		})
	}
}

func TestVersionCmd_Run_JSONStructure(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	// Create command with JSON output
	cmd := &VersionCmd{}
	ctx := &Context{
		JsonOutput: true,
	}

	// Run the command
	err = cmd.Run(ctx)
	assert.NoError(t, err)

	// Close writer and restore stdout
	w.Close()

	output, err := io.ReadAll(r)
	require.NoError(t, err)

	os.Stdout = oldStdout

	// Parse JSON
	var result map[string]string

	err = json.Unmarshal(output, &result)
	assert.NoError(t, err)

	// Verify JSON structure and content
	expectedFields := []string{"app", "version", "protocol"}
	for _, field := range expectedFields {
		assert.Contains(t, result, field, "JSON output should contain %s field", field)
		assert.NotEmpty(t, result[field], "%s field should not be empty", field)
	}

	// Verify specific values
	assert.Equal(t, strings.ToUpper(utils.ProjectName), result["app"])
	assert.Equal(t, utils.ProjectVersion, result["version"])
	assert.Equal(t, utils.ProtocolVersion, result["protocol"])
}

func TestVersionCmd_Run_PlainTextContent(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	// Create command with plain text output
	cmd := &VersionCmd{}
	ctx := &Context{
		JsonOutput: false,
	}

	// Run the command
	err = cmd.Run(ctx)
	assert.NoError(t, err)

	// Close writer and restore stdout
	w.Close()

	output, err := io.ReadAll(r)
	require.NoError(t, err)

	os.Stdout = oldStdout

	outputStr := string(output)

	// Verify the plain text contains expected content
	assert.Contains(t, outputStr, strings.ToUpper(utils.ProjectName))
	assert.Contains(t, outputStr, utils.ProjectVersion)
	assert.Contains(t, outputStr, utils.ProtocolVersion)
	assert.Contains(t, outputStr, "Version")
	assert.Contains(t, outputStr, "Protocol")
}

func TestVersionCmd_Run_JSONIndentation(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	// Create command with JSON output
	cmd := &VersionCmd{}
	ctx := &Context{
		JsonOutput: true,
	}

	// Run the command
	err = cmd.Run(ctx)
	assert.NoError(t, err)

	// Close writer and restore stdout
	w.Close()

	output, err := io.ReadAll(r)
	require.NoError(t, err)

	os.Stdout = oldStdout

	outputStr := string(output)

	// Verify JSON is properly indented (contains spaces for indentation)
	assert.Contains(t, outputStr, "  ", "JSON output should be indented")
	assert.Contains(t, outputStr, "{\n", "JSON should start with opening brace and newline")
	assert.Contains(t, outputStr, "\n}", "JSON should end with newline and closing brace")
}

func TestVersionCmd_Run_ContextNil(t *testing.T) {
	cmd := &VersionCmd{}

	// This should panic or return an error with nil context
	// We expect it to panic when accessing ctx.JsonOutput
	assert.Panics(t, func() {
		cmd.Run(nil)
	}, "Run should panic with nil context")
}

func TestVersionCmd_Run_EmptyContext(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	// Create command with empty context (JsonOutput defaults to false)
	cmd := &VersionCmd{}
	ctx := &Context{}

	// Run the command
	err = cmd.Run(ctx)
	assert.NoError(t, err)

	// Close writer and restore stdout
	w.Close()

	output, err := io.ReadAll(r)
	require.NoError(t, err)

	os.Stdout = oldStdout

	outputStr := string(output)

	// Should default to plain text output
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")
	assert.Len(t, lines, 3, "Empty context should default to plain text output with 3 lines")
}

// Test that verifies the version command works with different utils constants
func TestVersionCmd_Run_UtilsIntegration(t *testing.T) {
	tests := []struct {
		name       string
		jsonOutput bool
	}{
		{"plain text with utils", false},
		{"json with utils", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			require.NoError(t, err)

			os.Stdout = w

			cmd := &VersionCmd{}
			ctx := &Context{JsonOutput: tt.jsonOutput}

			err = cmd.Run(ctx)
			assert.NoError(t, err)

			w.Close()

			output, err := io.ReadAll(r)
			require.NoError(t, err)

			os.Stdout = oldStdout

			outputStr := string(output)

			// Verify that utils constants are being used correctly
			if tt.jsonOutput {
				var info map[string]string

				err := json.Unmarshal(output, &info)
				assert.NoError(t, err)
				assert.NotEmpty(t, info["app"])
				assert.NotEmpty(t, info["version"])
				assert.NotEmpty(t, info["protocol"])
			} else {
				assert.NotEmpty(t, outputStr)
				assert.NotEqual(t, "\n\n\n", outputStr, "Output should not be empty lines")
			}
		})
	}
}
