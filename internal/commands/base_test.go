/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// MockPasswordReader for testing password prompting
type MockPasswordReader struct {
	password string
	err      error
}

func (m *MockPasswordReader) ReadPassword() (string, error) {
	return m.password, m.err
}

// MockPasswordRequirer for testing password requirements
type MockPasswordRequirer struct {
	requiresPassword bool
}

func (m *MockPasswordRequirer) RequiresAMTPassword() bool {
	return m.requiresPassword
}

func TestAMTBaseCmd_Validate(t *testing.T) {
	tests := []struct {
		name          string
		initialPass   string
		mockPassword  string
		mockError     error
		requiresPass  bool
		expectedError bool
		expectedPass  string
	}{
		{
			name:         "password already provided",
			initialPass:  "existing-password",
			requiresPass: true,
			expectedPass: "existing-password",
		},
		{
			name:         "password prompted successfully",
			initialPass:  "",
			mockPassword: "prompted-password",
			requiresPass: true,
			expectedPass: "prompted-password",
		},
		{
			name:          "password prompting fails",
			initialPass:   "",
			mockError:     assert.AnError,
			requiresPass:  true,
			expectedError: true,
		},
		{
			name:         "no password required",
			initialPass:  "",
			requiresPass: false,
			expectedPass: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock password reader
			originalPR := utils.PR

			defer func() { utils.PR = originalPR }()

			utils.PR = &MockPasswordReader{
				password: tt.mockPassword,
				err:      tt.mockError,
			}

			cmd := &AMTBaseCmd{
				Password: tt.initialPass,
			}

			// Test the base Validate method (should always succeed)
			err := cmd.Validate()
			assert.NoError(t, err)

			// Test the ValidatePasswordIfNeeded method
			requirer := &MockPasswordRequirer{requiresPassword: tt.requiresPass}
			err = cmd.ValidatePasswordIfNeeded(requirer)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPass, cmd.GetPassword())
			}
		})
	}
}

func TestAMTBaseCmd_RequiresAMTPassword(t *testing.T) {
	cmd := &AMTBaseCmd{}
	assert.True(t, cmd.RequiresAMTPassword(), "AMTBaseCmd should require password by default")
}

func TestAMTBaseCmd_GetPassword(t *testing.T) {
	cmd := &AMTBaseCmd{Password: "test-password"}
	assert.Equal(t, "test-password", cmd.GetPassword())
}

func TestAMTBaseCmd_GetWSManClient(t *testing.T) {
	cmd := &AMTBaseCmd{}
	// Initially should be nil
	assert.Nil(t, cmd.GetWSManClient())
}
