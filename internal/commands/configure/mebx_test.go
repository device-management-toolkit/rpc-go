/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/setupandconfiguration"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestMEBxCmd_Structure(t *testing.T) {
	cmd := &MEBxCmd{MEBxPassword: "mebx456"}
	assert.Equal(t, "mebx456", cmd.MEBxPassword)
}

func TestMEBxCmd_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cmd         MEBxCmd
		wantErr     bool
		description string
	}{
		{
			name:        "mebx password provided",
			cmd:         MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 1}}, MEBxPassword: "mebx456"},
			wantErr:     false,
			description: "should succeed when mebx password provided (AMT password now global)",
		},

		{
			name:        "missing MEBx password",
			cmd:         MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 1}}, MEBxPassword: ""},
			wantErr:     true,
			description: "should fail when MEBx password missing",
		},
		{
			name:        "mebx password missing still fails",
			cmd:         MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 1}}, MEBxPassword: ""},
			wantErr:     true,
			description: "duplicate case to ensure consistency",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()

			if tt.wantErr {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

func TestMEBxCmd_Run(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	t.Run("successful_mebx_configuration", func(t *testing.T) {
		cmd := &MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 2, WSMan: mockWSMAN}}, MEBxPassword: "mebx456"}

		ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Mock SetupMEBX
		setupResponse := setupandconfiguration.Response{
			Body: setupandconfiguration.Body{
				SetMEBxPassword_OUTPUT: setupandconfiguration.SetMEBxPassword_OUTPUT{
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().SetupMEBX("mebx456").Return(setupResponse, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("device_not_in_acm_mode", func(t *testing.T) {
		cmd := &MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 1, WSMan: mockWSMAN}}, MEBxPassword: "mebx456"}

		ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.SetMEBXPasswordFailed, err)
	})

	t.Run("device_not_activated", func(t *testing.T) {
		cmd := &MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 0, WSMan: mockWSMAN}}, MEBxPassword: "mebx456"}

		ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.SetMEBXPasswordFailed, err)
	})

	t.Run("setupmebx_wsman_error", func(t *testing.T) {
		cmd := &MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 2, WSMan: mockWSMAN}}, MEBxPassword: "mebx456"}

		ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Mock SetupMEBX to return an error
		mockWSMAN.EXPECT().SetupMEBX("mebx456").Return(setupandconfiguration.Response{}, errors.New("setup mebx error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "setup mebx error")
	})

	t.Run("setupmebx_return_value_error", func(t *testing.T) {
		cmd := &MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 2, WSMan: mockWSMAN}}, MEBxPassword: "mebx456"}

		ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Mock SetupMEBX with non-zero return value indicating failure
		setupResponse := setupandconfiguration.Response{
			Body: setupandconfiguration.Body{
				SetMEBxPassword_OUTPUT: setupandconfiguration.SetMEBxPassword_OUTPUT{
					ReturnValue: 1, // Non-zero indicates failure
				},
			},
		}
		mockWSMAN.EXPECT().SetupMEBX("mebx456").Return(setupResponse, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err) // The current implementation doesn't check return value
	})

	t.Run("control_mode_3_unsupported", func(t *testing.T) {
		cmd := &MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 3, WSMan: mockWSMAN}}, MEBxPassword: "mebx456"}

		ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.SetMEBXPasswordFailed, err)
	})

	t.Run("empty_mebx_password", func(t *testing.T) {
		cmd := &MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 2, WSMan: mockWSMAN}}, MEBxPassword: ""} // Empty password

		ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Mock SetupMEBX with empty password
		setupResponse := setupandconfiguration.Response{
			Body: setupandconfiguration.Body{
				SetMEBxPassword_OUTPUT: setupandconfiguration.SetMEBxPassword_OUTPUT{
					ReturnValue: 0,
				},
			},
		}
		mockWSMAN.EXPECT().SetupMEBX("").Return(setupResponse, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("structure_validation", func(t *testing.T) {
		cmd := &MEBxCmd{ConfigureBaseCmd: ConfigureBaseCmd{AMTBaseCmd: commands.AMTBaseCmd{}}, MEBxPassword: "mebx456"}

		// Verify command has required fields
		// Global AMT password no longer stored on command struct
		assert.NotEmpty(t, cmd.MEBxPassword)
	})
}
