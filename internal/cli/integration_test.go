/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestCLIIntegration(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		setupMock      func(*mock.MockInterface)
		expectError    bool
		expectedCmd    string
		validateResult func(*testing.T, *CLI)
	}{
		{
			name: "version command",
			args: []string{"rpc", "version"},
			setupMock: func(m *mock.MockInterface) {
				// Version command doesn't need AMT initialization
			},
			expectError: false,
			expectedCmd: "version",
		},
		{
			name: "version command with json output",
			args: []string{"rpc", "version", "--json"},
			setupMock: func(m *mock.MockInterface) {
				// Version command doesn't need AMT initialization
			},
			expectError: false,
			expectedCmd: "version",
			validateResult: func(t *testing.T, cli *CLI) {
				assert.True(t, cli.JsonOutput)
			},
		},
		{
			name: "amtinfo command",
			args: []string{"rpc", "amtinfo"},
			setupMock: func(m *mock.MockInterface) {
				// AmtInfo might trigger Initialize during parsing and needs GetControlMode for AfterApply
				m.EXPECT().Initialize().Return(nil).AnyTimes()
				m.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), nil).AnyTimes()
				m.EXPECT().GetControlMode().Return(1, nil).AnyTimes()
			},
			expectError: false,
			expectedCmd: "amtinfo",
		},
		{
			name: "amtinfo with flags",
			args: []string{"rpc", "amtinfo", "--ver", "--sku", "--all"},
			setupMock: func(m *mock.MockInterface) {
				// AmtInfo might trigger Initialize during parsing and needs GetControlMode for AfterApply
				m.EXPECT().Initialize().Return(nil).AnyTimes()
				m.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), nil).AnyTimes()
				m.EXPECT().GetControlMode().Return(1, nil).AnyTimes()
			},
			expectError: false,
			expectedCmd: "amtinfo",
			validateResult: func(t *testing.T, cli *CLI) {
				assert.True(t, cli.AmtInfo.Ver)
				assert.True(t, cli.AmtInfo.Sku)
				assert.True(t, cli.AmtInfo.All)
			},
		},
		{
			name: "amtinfo with password",
			args: []string{"rpc", "amtinfo", "--cert", "--password", "test123"},
			setupMock: func(m *mock.MockInterface) {
				// AmtInfo might trigger Initialize during parsing and needs GetControlMode for AfterApply
				m.EXPECT().Initialize().Return(nil).AnyTimes()
				m.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), nil).AnyTimes()
				m.EXPECT().GetControlMode().Return(1, nil).AnyTimes()
			},
			expectError: false,
			expectedCmd: "amtinfo",
			validateResult: func(t *testing.T, cli *CLI) {
				assert.True(t, cli.AmtInfo.Cert)
				assert.Equal(t, "test123", cli.AmtInfo.Password)
			},
		},
		{
			name: "global verbose and json flags",
			args: []string{"rpc", "--verbose", "--json", "version"},
			setupMock: func(m *mock.MockInterface) {
				// Version command doesn't need AMT initialization
			},
			expectError: false,
			expectedCmd: "version",
			validateResult: func(t *testing.T, cli *CLI) {
				assert.True(t, cli.Verbose)
				assert.True(t, cli.JsonOutput)
			},
		},
		{
			name: "log level setting",
			args: []string{"rpc", "--log-level", "debug", "version"},
			setupMock: func(m *mock.MockInterface) {
				// Version command doesn't need AMT initialization
			},
			expectError: false,
			expectedCmd: "version",
			validateResult: func(t *testing.T, cli *CLI) {
				assert.Equal(t, "debug", cli.LogLevel)
			},
		},
		{
			name: "invalid command",
			args: []string{"rpc", "invalidcommand"},
			setupMock: func(m *mock.MockInterface) {
				// Don't expect Initialize to be called for invalid commands
			},
			expectError: true,
		},
		{
			name: "invalid flag",
			args: []string{"rpc", "version", "--invalid-flag"},
			setupMock: func(m *mock.MockInterface) {
				// Invalid flag should fail before any AMT calls
			},
			expectError: true,
		},
		{
			name: "no command provided",
			args: []string{"rpc"},
			setupMock: func(m *mock.MockInterface) {
				// No command should fail before any AMT calls
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAMT := mock.NewMockInterface(ctrl)
			if tt.setupMock != nil {
				tt.setupMock(mockAMT)
			}

			ctx, cli, err := Parse(tt.args, mockAMT)

			if tt.expectError {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, ctx)
			assert.NotNil(t, cli)

			if tt.expectedCmd != "" {
				assert.Equal(t, tt.expectedCmd, ctx.Selected().Name)
			}

			// Verify global settings are properly configured
			assert.Contains(t, []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}, cli.LogLevel)

			// Run custom validation if provided
			if tt.validateResult != nil {
				tt.validateResult(t, cli)
			}
		})
	}
}

func TestCLIArgumentValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorText   string
		description string
	}{
		{
			name:        "empty args",
			args:        []string{},
			expectError: true,
			errorText:   "expected one of",
			description: "should fail with empty args",
		},
		{
			name:        "program name only",
			args:        []string{"rpc"},
			expectError: true,
			errorText:   "expected one of",
			description: "should fail with no command",
		},
		{
			name:        "invalid command",
			args:        []string{"rpc", "invalidcommand"},
			expectError: true,
			errorText:   "unexpected argument",
			description: "should fail with invalid command",
		},
		{
			name:        "invalid flag",
			args:        []string{"rpc", "version", "--invalid-flag"},
			expectError: true,
			errorText:   "unknown flag",
			description: "should fail with invalid flag",
		},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAMT := mock.NewMockInterface(ctrl)
			// Allow Initialize to be called for amtinfo commands during parsing
			mockAMT.EXPECT().Initialize().Return(nil).AnyTimes()
			// Allow GetChangeEnabled to be called during AfterApply for amtinfo commands
			mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), nil).AnyTimes()
			// Allow GetControlMode to be called during AfterApply for amtinfo commands
			mockAMT.EXPECT().GetControlMode().Return(1, nil).AnyTimes()

			_, _, err := Parse(tt.args, mockAMT)

			if tt.expectError {
				assert.Error(t, err, tt.description)

				if tt.errorText != "" {
					assert.Contains(t, err.Error(), tt.errorText)
				}
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}
