/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		expected string
	}{
		{
			name:     "version command",
			args:     []string{"rpc", "version"},
			wantErr:  false,
			expected: "version",
		},
		{
			name:     "amtinfo command",
			args:     []string{"rpc", "amtinfo"},
			wantErr:  false,
			expected: "amtinfo",
		},
		{
			name:     "amtinfo with flags",
			args:     []string{"rpc", "amtinfo", "--ver", "--sku"},
			wantErr:  false,
			expected: "amtinfo",
		},
		// Note: Help tests are excluded because Kong calls os.Exit(0)
		// which cannot be tested in unit tests
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock controller and AMT command for testing
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAMT := mock.NewMockInterface(ctrl)

			// Set up mock expectations for commands that require AMT validation
			if tt.expected == "amtinfo" {
				// Mock GetChangeEnabled to return a response that doesn't enforce TLS on local ports
				mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), nil).AnyTimes()
				// Mock GetControlMode to return a valid provisioned state (1) for amtinfo validation
				mockAMT.EXPECT().GetControlMode().Return(1, nil).AnyTimes()
				// Mock Close to satisfy cleanup
				mockAMT.EXPECT().Close().Return(nil).AnyTimes()
			}

			ctx, cli, err := Parse(tt.args, mockAMT)

			if tt.wantErr {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, ctx)
			assert.NotNil(t, cli)

			if tt.expected != "" {
				// Check that the correct command was selected
				assert.Equal(t, tt.expected, ctx.Selected().Name)
			}
		})
	}
}

func TestGlobalsBeforeApply(t *testing.T) {
	tests := []struct {
		name    string
		globals Globals
		wantErr bool
	}{
		{
			name: "default settings",
			globals: Globals{
				LogLevel:   "info",
				JsonOutput: false,
				Verbose:    false,
			},
			wantErr: false,
		},
		{
			name: "verbose enabled",
			globals: Globals{
				LogLevel:   "info",
				JsonOutput: false,
				Verbose:    true,
			},
			wantErr: false,
		},
		{
			name: "json output enabled",
			globals: Globals{
				LogLevel:   "info",
				JsonOutput: true,
				Verbose:    false,
			},
			wantErr: false,
		},
		{
			name: "debug level",
			globals: Globals{
				LogLevel:   "debug",
				JsonOutput: false,
				Verbose:    false,
			},
			wantErr: false,
		},
		{
			name: "invalid log level",
			globals: Globals{
				LogLevel:   "invalid",
				JsonOutput: false,
				Verbose:    false,
			},
			wantErr: false, // Should not error, just warn and use default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.globals.AfterApply(nil)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
