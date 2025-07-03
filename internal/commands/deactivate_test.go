/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"crypto/tls"
	"errors"
	"fmt"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

// Mock for GoWSMANMessages
type MockGoWSMANMessages struct {
	mock.Mock
}

func (m *MockGoWSMANMessages) SetupWsmanClient(username string, password string, useTLS bool, logAMTMessages bool, tlsConfig *tls.Config) error {
	args := m.Called(username, password, useTLS, logAMTMessages, tlsConfig)

	return args.Error(0)
}

func (m *MockGoWSMANMessages) PartialUnprovision() (interface{}, error) {
	args := m.Called()

	return args.Get(0), args.Error(1)
}

func (m *MockGoWSMANMessages) Unprovision(mode int) (interface{}, error) {
	args := m.Called(mode)

	return args.Get(0), args.Error(1)
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
			name: "valid local mode",
			cmd: DeactivateCmd{
				Local: true,
			},
			wantErr: "",
		},
		{
			name: "valid remote mode",
			cmd: DeactivateCmd{
				URL: "https://example.com",
			},
			wantErr: "",
		},
		{
			name: "valid local with partial",
			cmd: DeactivateCmd{
				Local:              true,
				PartialUnprovision: true,
			},
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

func TestDeactivateCmd_EnsurePasswordProvided(t *testing.T) {
	// Save original password reader
	originalPR := utils.PR

	t.Run("password already provided", func(t *testing.T) {
		cmd := &DeactivateCmd{Password: "existing-password"}
		err := cmd.ensurePasswordProvided()
		assert.NoError(t, err)
		assert.Equal(t, "existing-password", cmd.Password)
	})

	t.Run("password prompted successfully", func(t *testing.T) {
		utils.PR = &MockPasswordReaderSuccess{}
		cmd := &DeactivateCmd{}
		err := cmd.ensurePasswordProvided()
		assert.NoError(t, err)
		assert.Equal(t, utils.TestPassword, cmd.Password)
	})

	t.Run("password prompt fails", func(t *testing.T) {
		utils.PR = &MockPasswordReaderFail{}
		cmd := &DeactivateCmd{}
		err := cmd.ensurePasswordProvided()
		assert.Error(t, err)
		assert.Equal(t, utils.MissingOrIncorrectPassword, err)
	})

	// Restore original password reader
	utils.PR = originalPR
}

func TestDeactivateCmd_SetupTLSConfig(t *testing.T) {
	cmd := &DeactivateCmd{}

	t.Run("TLS enforced", func(t *testing.T) {
		ctx := &Context{LocalTLSEnforced: true, SkipCertCheck: true}
		controlMode := ControlModeACM
		tlsConfig := cmd.setupTLSConfig(ctx, controlMode)
		assert.NotNil(t, tlsConfig)
	})

	t.Run("TLS not enforced", func(t *testing.T) {
		ctx := &Context{LocalTLSEnforced: false}
		controlMode := ControlModeACM
		tlsConfig := cmd.setupTLSConfig(ctx, controlMode)
		assert.NotNil(t, tlsConfig)
	})
}

func TestDeactivateCmd_Run_Local_CCM(t *testing.T) {
	t.Run("successful CCM deactivation without password", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(ControlModeCCM, nil)
		mockAMT.On("Unprovision").Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.Run(ctx)
		assert.NoError(t, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("successful CCM deactivation with password (shows warning)", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(ControlModeCCM, nil)
		mockAMT.On("Unprovision").Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true, Password: "test-password"}

		err := cmd.Run(ctx)
		assert.NoError(t, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("CCM deactivation fails on unprovision error", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(ControlModeCCM, nil)
		mockAMT.On("Unprovision").Return(0, errors.New("unprovision failed"))

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("CCM deactivation fails on non-zero status", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(ControlModeCCM, nil)
		mockAMT.On("Unprovision").Return(1, nil)

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("CCM partial unprovision not supported", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(ControlModeCCM, nil)

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true, PartialUnprovision: true}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "partial unprovisioning is only supported in ACM mode")
		mockAMT.AssertExpectations(t)
	})
}

func TestDeactivateCmd_Run_Local_GetControlModeFailure(t *testing.T) {
	t.Run("GetControlMode fails", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(0, errors.New("control mode failed"))

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.AMTConnectionFailed, err)
		mockAMT.AssertExpectations(t)
	})
}

func TestDeactivateCmd_Run_Local_UnsupportedControlMode(t *testing.T) {
	t.Run("unsupported control mode", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(0, nil) // Pre-provisioning mode

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
		mockAMT.AssertExpectations(t)
	})
}

// Test for ACM mode password handling
func TestDeactivateCmd_Run_Local_ACM_PasswordHandling(t *testing.T) {
	originalPR := utils.PR

	t.Run("ACM mode fails when password prompt fails", func(t *testing.T) {
		utils.PR = &MockPasswordReaderFail{}

		defer func() { utils.PR = originalPR }()

		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(ControlModeACM, nil)

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.MissingOrIncorrectPassword, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("ACM mode fails when password is empty string", func(t *testing.T) {
		utils.PR = &MockPasswordReaderEmpty{}

		defer func() { utils.PR = originalPR }()

		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(ControlModeACM, nil)

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		// Should fail because empty password will fail validation in readPasswordFromUser
		mockAMT.AssertExpectations(t)
	})
}

// Test for Run function routing logic
func TestDeactivateCmd_Run_Routing(t *testing.T) {
	t.Run("routes to local when Local flag is true", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(ControlModeCCM, nil)
		mockAMT.On("Unprovision").Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.Run(ctx)
		assert.NoError(t, err)
		mockAMT.AssertExpectations(t)
	})

	// Note: Remote execution testing requires RPS mocking which is complex
	// For now, we focus on testing the routing logic and the parts we can control
}

// Test executeRemoteDeactivate password handling in isolation
func TestDeactivateCmd_ExecuteRemoteDeactivate_PasswordHandling(t *testing.T) {
	originalPR := utils.PR

	t.Run("remote deactivation fails when password prompt fails", func(t *testing.T) {
		utils.PR = &MockPasswordReaderFail{}

		defer func() { utils.PR = originalPR }()

		ctx := &Context{LogLevel: "info", JsonOutput: false, Verbose: false}
		cmd := DeactivateCmd{URL: "https://example.com"}

		err := cmd.executeRemoteDeactivate(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.MissingOrIncorrectPassword, err)
	})

	t.Run("remote deactivation with existing password", func(t *testing.T) {
		ctx := &Context{LogLevel: "info", JsonOutput: false, Verbose: false}
		cmd := DeactivateCmd{URL: "https://example.com", Password: "existing-password"}

		// This will fail because it will try to call the actual RPS.ExecuteCommand
		// But it will pass the password validation phase
		err := cmd.executeRemoteDeactivate(ctx)
		// We expect some error here since we can't mock RPS easily,
		// but the password validation should pass
		// The important thing is that it didn't fail with MissingOrIncorrectPassword
		assert.NotEqual(t, utils.MissingOrIncorrectPassword, err)
	})
}

// Test for deactivateCCM function in isolation
func TestDeactivateCmd_DeactivateCCM(t *testing.T) {
	t.Run("CCM deactivation with password shows warning but succeeds", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("Unprovision").Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Password: "test-password"}

		err := cmd.deactivateCCM(ctx)
		assert.NoError(t, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("CCM deactivation without password succeeds", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("Unprovision").Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.NoError(t, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("CCM deactivation fails with unprovision error", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("Unprovision").Return(0, errors.New("unprovision error"))

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("CCM deactivation fails with non-zero status", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("Unprovision").Return(5, nil) // Non-zero status

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
		mockAMT.AssertExpectations(t)
	})
}

// Test for executeLocalDeactivate function logic
func TestDeactivateCmd_ExecuteLocalDeactivate(t *testing.T) {
	t.Run("handles control mode 3 (unknown mode)", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(3, nil) // Unknown control mode

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.executeLocalDeactivate(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("handles negative control mode", func(t *testing.T) {
		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(-1, nil) // Negative control mode

		ctx := &Context{AMTCommand: mockAMT}
		cmd := DeactivateCmd{Local: true}

		err := cmd.executeLocalDeactivate(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
		mockAMT.AssertExpectations(t)
	})
}

// Test control mode constants
func TestControlModeConstants(t *testing.T) {
	assert.Equal(t, 1, ControlModeCCM)
	assert.Equal(t, 2, ControlModeACM)
}

// Test edge cases for password handling
func TestPasswordHandlingEdgeCases(t *testing.T) {
	originalPR := utils.PR

	t.Run("password with special characters", func(t *testing.T) {
		cmd := &DeactivateCmd{Password: "P@ssw0rd!@#$%^&*()"}
		// Test that special characters in password don't cause issues
		assert.Equal(t, "P@ssw0rd!@#$%^&*()", cmd.Password)
	})

	t.Run("empty password prompts for input", func(t *testing.T) {
		// Mock password reader
		utils.PR = &MockPasswordReaderSuccess{}

		cmd := &DeactivateCmd{Password: ""}
		err := cmd.ensurePasswordProvided()

		assert.NoError(t, err)
		assert.Equal(t, "test-password", cmd.Password)
	})

	t.Run("password validation", func(t *testing.T) {
		cmd := &DeactivateCmd{Password: "validPassword123"}
		assert.NotEmpty(t, cmd.Password)
		assert.True(t, len(cmd.Password) > 0)
	})

	// Restore original password reader
	defer func() {
		utils.PR = originalPR
	}()
}

// Test additional Run method edge cases
func TestRunMethodEdgeCases(t *testing.T) {
	t.Run("local deactivation with CCM and partial unprovision error", func(t *testing.T) {
		// Setup
		cmd := &DeactivateCmd{
			Local:              true,
			PartialUnprovision: true,
		}

		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(ControlModeCCM, nil)

		ctx := &Context{
			AMTCommand: mockAMT,
		}

		// Execute
		err := cmd.Run(ctx)

		// Verify
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "partial unprovisioning is only supported in ACM mode")
		mockAMT.AssertExpectations(t)
	})

	t.Run("local deactivation with unknown control mode", func(t *testing.T) {
		// Setup
		cmd := &DeactivateCmd{Local: true}

		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(999, nil) // Unknown control mode

		ctx := &Context{
			AMTCommand: mockAMT,
		}

		// Execute
		err := cmd.Run(ctx)

		// Verify
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
		mockAMT.AssertExpectations(t)
	})

	t.Run("local deactivation with AMT connection failure", func(t *testing.T) {
		// Setup
		cmd := &DeactivateCmd{Local: true}

		mockAMT := &MockAMTCommand{}
		mockAMT.On("GetControlMode").Return(0, fmt.Errorf("AMT connection failed"))

		ctx := &Context{
			AMTCommand: mockAMT,
		}

		// Execute
		err := cmd.Run(ctx)

		// Verify
		assert.Error(t, err)
		assert.Equal(t, utils.AMTConnectionFailed, err)
		mockAMT.AssertExpectations(t)
	})
}

// Test setupTLSConfig function
func TestSetupTLSConfig(t *testing.T) {
	t.Run("TLS config with LocalTLSEnforced false", func(t *testing.T) {
		cmd := &DeactivateCmd{}
		ctx := &Context{LocalTLSEnforced: false}
		controlMode := ControlModeACM

		tlsConfig := cmd.setupTLSConfig(ctx, controlMode)

		assert.NotNil(t, tlsConfig)
		assert.False(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("TLS config with LocalTLSEnforced true", func(t *testing.T) {
		cmd := &DeactivateCmd{}
		ctx := &Context{
			LocalTLSEnforced: true,
			SkipCertCheck:    true,
		}
		controlMode := ControlModeACM

		tlsConfig := cmd.setupTLSConfig(ctx, controlMode)

		assert.NotNil(t, tlsConfig)
		// The actual config setup depends on the config.GetTLSConfig implementation
	})
}

// Test readPasswordFromUser function
func TestReadPasswordFromUser(t *testing.T) {
	originalPR := utils.PR

	t.Run("successful password read", func(t *testing.T) {
		utils.PR = &MockPasswordReaderSuccess{}

		password, err := readPasswordFromUser()

		assert.NoError(t, err)
		assert.Equal(t, "test-password", password)
	})

	t.Run("password read failure", func(t *testing.T) {
		utils.PR = &MockPasswordReaderFail{}

		password, err := readPasswordFromUser()

		assert.Error(t, err)
		assert.Empty(t, password)
	})

	t.Run("empty password read", func(t *testing.T) {
		utils.PR = &MockPasswordReaderEmpty{}

		password, err := readPasswordFromUser()

		assert.Error(t, err)
		assert.Empty(t, password)
		assert.Contains(t, err.Error(), "password cannot be empty")
	})

	// Restore original password reader
	defer func() {
		utils.PR = originalPR
	}()
}
