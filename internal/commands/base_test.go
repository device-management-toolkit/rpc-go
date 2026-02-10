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
	passwords []string // passwords to return in sequence
	index     int
	err       error
}

func (m *MockPasswordReader) ReadPassword() (string, error) {
	if m.err != nil {
		return "", m.err
	}

	if len(m.passwords) == 0 {
		return "", nil
	}

	pw := m.passwords[m.index]
	if m.index < len(m.passwords)-1 {
		m.index++
	}

	return pw, nil
}

func (m *MockPasswordReader) ReadPasswordWithConfirmation(prompt, confirmPrompt string) (string, error) {
	if m.err != nil {
		return "", m.err
	}

	if len(m.passwords) < 2 {
		// Single password means both are the same (matching)
		if len(m.passwords) == 1 {
			return m.passwords[0], nil
		}

		return "", nil
	}

	pw1 := m.passwords[0]
	pw2 := m.passwords[1]
	m.index = 2

	if pw1 != pw2 {
		return "", utils.PasswordsDoNotMatch
	}

	return pw1, nil
}

// MockPasswordRequirer for testing password requirements
type MockPasswordRequirer struct {
	requiresPassword bool
}

func (m *MockPasswordRequirer) RequiresAMTPassword() bool {
	return m.requiresPassword
}

func TestAMTBaseCmd_EnsureAMTPassword(t *testing.T) {
	tests := []struct {
		name          string
		ctxPassword   string
		mockPasswords []string
		mockError     error
		requiresPass  bool
		controlMode   int
		expectedError bool
		expectedPass  string
	}{
		{
			name:         "password already in context",
			ctxPassword:  "existing-password",
			requiresPass: true,
			expectedPass: "existing-password",
		},
		{
			name:          "password prompted successfully - activated device",
			mockPasswords: []string{"prompted-password"},
			requiresPass:  true,
			controlMode:   1, // activated (CCM)
			expectedPass:  "prompted-password",
		},
		{
			name:          "password prompted successfully - not activated with matching confirmation",
			mockPasswords: []string{"new-password", "new-password"},
			requiresPass:  true,
			controlMode:   0, // not activated
			expectedPass:  "new-password",
		},
		{
			name:          "password mismatch - not activated device",
			mockPasswords: []string{"password1", "password2"},
			requiresPass:  true,
			controlMode:   0, // not activated
			expectedError: true,
		},
		{
			name:          "password prompting fails",
			mockError:     assert.AnError,
			requiresPass:  true,
			expectedError: true,
		},
		{
			name:         "no password required - skip prompt",
			requiresPass: false,
			expectedPass: "",
		},
		{
			name:          "activated device ACM - single prompt",
			mockPasswords: []string{"acm-password"},
			requiresPass:  true,
			controlMode:   2, // activated (ACM)
			expectedPass:  "acm-password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalPR := utils.PR

			defer func() { utils.PR = originalPR }()

			utils.PR = &MockPasswordReader{passwords: tt.mockPasswords, err: tt.mockError}

			cmd := &AMTBaseCmd{ControlMode: tt.controlMode}
			ctx := &Context{AMTPassword: tt.ctxPassword}
			requirer := &MockPasswordRequirer{requiresPassword: tt.requiresPass}

			err := cmd.EnsureAMTPassword(ctx, requirer)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPass, ctx.AMTPassword)
			}
		})
	}
}

func TestAMTBaseCmd_EnsureAMTPassword_PasswordsDoNotMatch(t *testing.T) {
	originalPR := utils.PR

	defer func() { utils.PR = originalPR }()

	utils.PR = &MockPasswordReader{passwords: []string{"pass1", "pass2"}}

	cmd := &AMTBaseCmd{ControlMode: 0} // not activated
	ctx := &Context{}
	requirer := &MockPasswordRequirer{requiresPassword: true}

	err := cmd.EnsureAMTPassword(ctx, requirer)
	assert.Error(t, err)
	assert.ErrorIs(t, err, utils.PasswordsDoNotMatch)
}

func TestAMTBaseCmd_RequiresAMTPassword(t *testing.T) {
	cmd := &AMTBaseCmd{}
	assert.True(t, cmd.RequiresAMTPassword(), "AMTBaseCmd should require password by default")
}

// GetPassword removed with context-based password; test replaced by EnsureAMTPassword coverage.

func TestAMTBaseCmd_GetWSManClient(t *testing.T) {
	cmd := &AMTBaseCmd{}
	// Initially should be nil
	assert.Nil(t, cmd.GetWSManClient())
}
