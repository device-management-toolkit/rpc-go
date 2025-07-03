/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// MockAMTCommandForIntegration extends MockAMTCommand for integration testing
type MockAMTCommandForIntegration struct {
	MockAMTCommand
}

func TestExecuteIntegration(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		setupMock   func(*MockAMTCommand)
		expectError bool
		skipAMTInit bool
	}{
		{
			name: "version command success",
			args: []string{"rpc", "version"},
			setupMock: func(m *MockAMTCommand) {
				m.On("Initialize").Return(nil)
			},
			expectError: false,
		}, {
			name: "version command with json output",
			args: []string{"rpc", "version", "--json"},
			setupMock: func(m *MockAMTCommand) {
				m.On("Initialize").Return(nil)
			},
			expectError: false,
		},
		{
			name: "amtinfo command with specific flags",
			args: []string{"rpc", "amtinfo", "--ver", "--sku"},
			setupMock: func(m *MockAMTCommand) {
				m.On("Initialize").Return(nil)
			},
			expectError: false,
		},
		{
			name: "invalid command",
			args: []string{"rpc", "invalid"},
			setupMock: func(m *MockAMTCommand) {
				// Don't expect Initialize to be called for invalid commands
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This test is designed to verify the CLI parsing logic.
			// The actual Execute function calls amt.NewAMTCommand() which would
			// require AMT hardware to be present. In a real test environment,
			// you would need to mock the amt.NewAMTCommand() function or
			// refactor the Execute function to accept an AMTCommand interface.
			// For now, we test the Parse function which is the core of our changes
			mockAMT := &MockAMTCommandForIntegration{}

			ctx, cli, err := Parse(tt.args, mockAMT)
			if tt.expectError {
				// For invalid commands, we expect Kong to return an error
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, ctx)
			assert.NotNil(t, cli)

			// Verify the global settings are properly configured
			assert.Contains(t, []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}, cli.LogLevel)
		})
	}
}

func TestParseArgsValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		description string
	}{
		{
			name:        "empty args",
			args:        []string{},
			expectError: true,
			description: "should fail with empty args",
		},
		{
			name:        "program name only",
			args:        []string{"rpc"},
			expectError: true,
			description: "should fail with no command",
		},
		// Note: Help tests excluded because Kong calls os.Exit(0)
		{
			name:        "valid version command",
			args:        []string{"rpc", "version"},
			expectError: false,
			description: "valid version command should parse successfully",
		},
		{
			name:        "valid amtinfo command",
			args:        []string{"rpc", "amtinfo"},
			expectError: false,
			description: "valid amtinfo command should parse successfully",
		},
		{
			name:        "amtinfo with valid flags",
			args:        []string{"rpc", "amtinfo", "--ver", "--sku", "--all"},
			expectError: false,
			description: "amtinfo with flags should parse successfully",
		},
		{
			name:        "global verbose flag",
			args:        []string{"rpc", "--verbose", "version"},
			expectError: false,
			description: "global flags should work with commands",
		},
		{
			name:        "global json flag",
			args:        []string{"rpc", "--json", "amtinfo"},
			expectError: false,
			description: "global json flag should work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAMT := &MockAMTCommandForIntegration{}
			_, _, err := Parse(tt.args, mockAMT)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}
