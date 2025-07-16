/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/authorization"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAMTPasswordCmd_Structure(t *testing.T) {
	// Test that AMTPasswordCmd has the correct structure
	cmd := &AMTPasswordCmd{}

	// Test basic field access to ensure struct is correct
	cmd.Password = "test123"
	cmd.NewPassword = "newtest456"

	assert.Equal(t, "test123", cmd.Password)
	assert.Equal(t, "newtest456", cmd.NewPassword)
}

func TestAMTPasswordCmd_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cmd         AMTPasswordCmd
		wantErr     bool
		description string
	}{
		{
			name: "both_passwords_provided",
			cmd: AMTPasswordCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "current123",
					},
				},
				NewPassword: "new456",
			},
			wantErr:     false,
			description: "should succeed when both passwords are provided",
		},

		{
			name: "missing_new_password",
			cmd: AMTPasswordCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "current123",
					},
				},
				NewPassword: "", // Will be prompted
			},
			wantErr:     true, // Will fail in test since no interactive input
			description: "should prompt for new password when missing",
		},
		{
			name: "both_passwords_missing",
			cmd: AMTPasswordCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "",
					},
				},
				NewPassword: "",
			},
			wantErr:     true,
			description: "should fail when both passwords are missing",
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

func TestAMTPasswordCmd_Run(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	t.Run("successful_password_change", func(t *testing.T) {
		cmd := &AMTPasswordCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "current123",
					WSMan:       mockWSMAN,
				},
			},
			NewPassword: "new456",
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock GetGeneralSettings
		generalResponse := general.Response{
			Body: general.Body{
				GetResponse: general.GeneralSettingsResponse{
					DigestRealm: "Digest:50E15C1BFEE3CE7FD38F7B7E90824E01",
				},
			},
		}
		mockWSMAN.EXPECT().GetGeneralSettings().Return(generalResponse, nil)

		// Mock UpdateAMTPassword
		mockWSMAN.EXPECT().UpdateAMTPassword(gomock.Any()).Return(authorization.Response{}, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("device_not_activated", func(t *testing.T) {
		cmd := &AMTPasswordCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 0, // Not activated
					Password:    "current123",
					WSMan:       mockWSMAN,
				},
			},
			NewPassword: "new456",
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device is not activated")
	})

	t.Run("get_general_settings_error", func(t *testing.T) {
		cmd := &AMTPasswordCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1, // Set control mode to 1 (activated)
					Password:    "current123",
					WSMan:       mockWSMAN,
				},
			},
			NewPassword: "new456",
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock GetGeneralSettings to return an error
		mockWSMAN.EXPECT().GetGeneralSettings().Return(general.Response{}, errors.New("general settings error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get AMT general settings")
	})

	t.Run("update_password_error", func(t *testing.T) {
		cmd := &AMTPasswordCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "current123",
					WSMan:       mockWSMAN,
				},
			},
			NewPassword: "new456",
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock GetGeneralSettings
		generalResponse := general.Response{
			Body: general.Body{
				GetResponse: general.GeneralSettingsResponse{
					DigestRealm: "Digest:50E15C1BFEE3CE7FD38F7B7E90824E01",
				},
			},
		}
		mockWSMAN.EXPECT().GetGeneralSettings().Return(generalResponse, nil)

		// Mock UpdateAMTPassword to return an error
		mockWSMAN.EXPECT().UpdateAMTPassword(gomock.Any()).Return(authorization.Response{}, errors.New("update password error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update AMT password")
	})

	t.Run("structure_validation", func(t *testing.T) {
		cmd := &AMTPasswordCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					Password: "current123",
				},
			},
			NewPassword: "new456",
		}

		// Verify command has required fields
		assert.NotEmpty(t, cmd.Password)
		assert.NotEmpty(t, cmd.NewPassword)
	})
}
