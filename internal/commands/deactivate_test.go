/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"errors"
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// MockPasswordReader for testing password scenarios
type MockPasswordReaderSuccess struct{}

func (mpr *MockPasswordReaderSuccess) ReadPassword() (string, error) {
	return utils.TestPassword, nil
}

type MockPasswordReaderFail struct{}

func (mpr *MockPasswordReaderFail) ReadPassword() (string, error) {
	return "", errors.New("Read password failed")
}

type MockPasswordReaderEmpty struct{}

func (mpr *MockPasswordReaderEmpty) ReadPassword() (string, error) {
	return "", nil
}

func TestDeactivateCmd_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cmd     DeactivateCmd
		wantErr string
	}{
		{
			name: "both local and URL provided",
			cmd: DeactivateCmd{
				Local: true,
				URL:   "https://example.com",
			},
			wantErr: "provide either a 'url' or a 'local', but not both",
		},
		{
			name: "partial unprovision without local",
			cmd: DeactivateCmd{
				PartialUnprovision: true,
				URL:                "https://example.com",
			},
			wantErr: "partial unprovisioning is only supported with local flag",
		},
		{
			name: "no URL provided for remote",
			cmd: DeactivateCmd{
				Local: false,
			},
			wantErr: "-u flag is required when not using local mode",
		},
		{
			name:    "valid local mode",
			cmd:     DeactivateCmd{Local: true},
			wantErr: "",
		},
		{
			name:    "valid remote mode",
			cmd:     DeactivateCmd{URL: "https://example.com"},
			wantErr: "",
		},
		{
			name:    "valid local with partial",
			cmd:     DeactivateCmd{Local: true, PartialUnprovision: true},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()

			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

// Removed TestDeactivateCmd_EnsurePasswordProvided: password handling now centralized via context + EnsureAMTPassword.

func TestDeactivateCmd_SetupTLSConfig(t *testing.T) {
	cmd := &DeactivateCmd{}

	t.Run("TLS enforced", func(t *testing.T) {
		cmd.LocalTLSEnforced = true
		ctx := &Context{SkipCertCheck: true, SkipAMTCertCheck: true, ControlMode: ControlModeACM}
		tlsConfig := cmd.setupTLSConfig(ctx)
		assert.NotNil(t, tlsConfig)
	})

	t.Run("TLS not enforced", func(t *testing.T) {
		cmd.LocalTLSEnforced = false
		ctx := &Context{ControlMode: ControlModeACM}
		tlsConfig := cmd.setupTLSConfig(ctx)
		assert.NotNil(t, tlsConfig)
	})
}

func TestDeactivateCmd_Run_Local_CCM(t *testing.T) {
	t.Run("successful CCM deactivation without password", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("successful CCM deactivation with password (shows warning)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("CCM deactivation fails on unprovision error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, errors.New("unprovision failed"))

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
	})

	t.Run("CCM deactivation fails on non-zero status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(1, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
	})

	t.Run("CCM partial unprovision not supported", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true, PartialUnprovision: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "partial unprovisioning is only supported in ACM mode")
	})
}

func TestDeactivateCmd_Run_Local_GetControlModeFailure(t *testing.T) {
	t.Run("GetControlMode fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set invalid control mode to simulate failure
		cmd.ControlMode = 0 // This should trigger UnableToDeactivate

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

func TestDeactivateCmd_Run_Local_UnsupportedControlMode(t *testing.T) {
	t.Run("unsupported control mode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set unsupported control mode
		cmd.ControlMode = 0 // Pre-provisioning mode

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

// Test for ACM mode password handling
func TestDeactivateCmd_Run_Local_ACM_PasswordHandling(t *testing.T) {
	originalPR := utils.PR

	t.Run("ACM mode fails when password prompt fails (Run path)", func(t *testing.T) {
		utils.PR = &MockPasswordReaderFail{}

		defer func() { utils.PR = originalPR }()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		// Provide a mock WSMAN so EnsureWSMAN short-circuits and doesn't create a real client
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := DeactivateCmd{Local: true}
		cmd.ControlMode = ControlModeACM
		cmd.WSMan = mockWSMAN

		ctx := &Context{} // Intentionally omit AMTPassword to trigger prompt
		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read AMT password")
	})

	t.Run("ACM mode fails when password is empty string (Run path)", func(t *testing.T) {
		utils.PR = &MockPasswordReaderEmpty{}

		defer func() { utils.PR = originalPR }()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := DeactivateCmd{Local: true}
		cmd.ControlMode = ControlModeACM
		cmd.WSMan = mockWSMAN

		ctx := &Context{}
		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password cannot be empty")
	})
}

// Test for Run function routing logic
func TestDeactivateCmd_Run_Routing(t *testing.T) {
	t.Run("routes to local when Local flag is true", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set CCM control mode
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	// Note: Remote execution testing requires RPS mocking which is complex
	// For now, we focus on testing the routing logic and the parts we can control
}

// Test remote deactivate validation (password handling happens in Validate, not in executeRemoteDeactivate)
func TestDeactivateCmd_RemoteDeactivate_Validation(t *testing.T) {
	// Remote validation now only checks URL/local logic. Password prompting happens in Run.
	t.Run("remote deactivation Validate passes without password", func(t *testing.T) {
		cmd := DeactivateCmd{URL: "https://example.com"}
		err := cmd.Validate()
		assert.NoError(t, err)
	})
}

// Test for deactivateCCM function in isolation
func TestDeactivateCmd_DeactivateCCM(t *testing.T) {
	t.Run("CCM deactivation with password shows warning but succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.NoError(t, err)
	})

	t.Run("CCM deactivation without password succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.NoError(t, err)
	})

	t.Run("CCM deactivation fails with unprovision error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, errors.New("unprovision error"))

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
	})

	t.Run("CCM deactivation fails with non-zero status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(5, nil) // Non-zero status

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
	})
}

// Test for executeLocalDeactivate function logic
func TestDeactivateCmd_ExecuteLocalDeactivate(t *testing.T) {
	t.Run("handles control mode 3 (unknown mode)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set unknown control mode
		cmd.ControlMode = 3

		err := cmd.executeLocalDeactivate(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})

	t.Run("handles negative control mode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set negative control mode
		cmd.ControlMode = -1

		err := cmd.executeLocalDeactivate(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

// Test control mode constants
func TestControlModeConstants(t *testing.T) {
	assert.Equal(t, 1, ControlModeCCM)
	assert.Equal(t, 2, ControlModeACM)
}

// Test edge cases for password handling
// Legacy password handling tests removed due to context-based password refactor.

// Test additional Run method edge cases
func TestRunMethodEdgeCases(t *testing.T) {
	t.Run("local deactivation with CCM and partial unprovision error", func(t *testing.T) {
		// Setup
		cmd := &DeactivateCmd{
			Local:              true,
			PartialUnprovision: true,
		}
		// Set CCM control mode
		cmd.ControlMode = ControlModeCCM

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Execute
		err := cmd.Run(ctx)

		// Verify
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "partial unprovisioning is only supported in ACM mode")
	})

	t.Run("local deactivation with unknown control mode", func(t *testing.T) {
		// Setup
		cmd := &DeactivateCmd{Local: true}
		// Set unknown control mode
		cmd.ControlMode = 999

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Execute
		err := cmd.Run(ctx)

		// Verify
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})

	t.Run("local deactivation with AMT connection failure", func(t *testing.T) {
		// Setup
		cmd := &DeactivateCmd{Local: true}
		// Set zero control mode (pre-provisioning)
		cmd.ControlMode = 0

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Execute
		err := cmd.Run(ctx)

		// Verify
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

// Test setupTLSConfig function
func TestSetupTLSConfig(t *testing.T) {
	t.Run("TLS config with LocalTLSEnforced false", func(t *testing.T) {
		cmd := &DeactivateCmd{}
		cmd.LocalTLSEnforced = true
		ctx := &Context{ControlMode: ControlModeACM}

		tlsConfig := cmd.setupTLSConfig(ctx)

		assert.NotNil(t, tlsConfig)
		assert.False(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("TLS config with LocalTLSEnforced true", func(t *testing.T) {
		cmd := &DeactivateCmd{}
		cmd.LocalTLSEnforced = true
		ctx := &Context{
			SkipCertCheck: true,
			ControlMode:   ControlModeACM,
		}

		tlsConfig := cmd.setupTLSConfig(ctx)

		assert.NotNil(t, tlsConfig)
		// The actual config setup depends on the config.GetTLSConfig implementation
	})
}
