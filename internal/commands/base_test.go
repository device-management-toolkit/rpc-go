/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"errors"
	"fmt"
	"testing"
	"time"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
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

func TestAMTBaseCmd_AMTTLSConfig_FollowsContextSkipAMTCertCheck(t *testing.T) {
	// ACM: the TLS config verifies AMT's certificate unless the caller skips it.
	cmd := &AMTBaseCmd{ControlMode: 2}

	assert.True(t, cmd.amtTLSConfig(&Context{SkipAMTCertCheck: true}).InsecureSkipVerify)
	assert.False(t, cmd.amtTLSConfig(&Context{SkipAMTCertCheck: false}).InsecureSkipVerify)
}

func TestAMTBaseCmd_GetWSManClient(t *testing.T) {
	cmd := &AMTBaseCmd{}
	// Initially should be nil
	assert.Nil(t, cmd.GetWSManClient())
}

func TestIsPermanentHECIError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"device not found", heci.ErrDeviceNotFound, true},
		{"wrapped device not found", fmt.Errorf("open failed: %w", heci.ErrDeviceNotFound), true},
		{"unsupported HECI operation", heci.ErrUnsupportedDevice, true},
		{"HECIDriverNotDetected sentinel", utils.HECIDriverNotDetected, true},
		{"permission denied", heci.ErrPermissionDenied, true},
		{"transient error", errors.New("temporary ME busy"), false},
		{"generic error", errors.New("some other error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isPermanentHECIError(tt.err))
		})
	}
}

func TestAMTBaseCmd_AfterApplySuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	amtCommand.EXPECT().Close().Return(nil)
	amtCommand.EXPECT().GetControlMode().Return(2, nil)
	amtCommand.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), nil)

	cmd := &AMTBaseCmd{}
	err := cmd.afterApply(amtCommand, true, "amd64", func(time.Duration) {})

	require.NoError(t, err)
	assert.Equal(t, 2, cmd.ControlMode)
	assert.True(t, cmd.HECIAvailable)
	assert.True(t, cmd.afterApplied)
}

func TestAMTBaseCmd_AfterApplyUnprivileged(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantErr     error
		wantCause   error
		wantApplied bool
	}{
		{name: "missing device", err: heci.ErrDeviceNotFound, wantErr: utils.HECIDriverNotDetected, wantCause: heci.ErrDeviceNotFound},
		{name: "unsupported device", err: heci.ErrUnsupportedDevice, wantErr: utils.AmtNotDetected, wantCause: heci.ErrUnsupportedDevice},
		{name: "permission denied", err: heci.ErrPermissionDenied, wantErr: utils.IncorrectPermissions, wantCause: heci.ErrPermissionDenied},
		{name: "transient failure requests elevation", err: errors.New("ME busy"), wantErr: utils.IncorrectPermissions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			amtCommand := mock.NewMockInterface(ctrl)
			amtCommand.EXPECT().Close().Return(nil)
			amtCommand.EXPECT().GetControlMode().Return(0, tt.err)

			cmd := &AMTBaseCmd{}
			err := cmd.afterApply(amtCommand, false, "amd64", func(time.Duration) {})

			assert.ErrorIs(t, err, tt.wantErr)

			if tt.wantCause != nil {
				assert.ErrorIs(t, err, tt.wantCause)
			}

			assert.Equal(t, tt.wantApplied, cmd.afterApplied)
		})
	}
}

func TestAMTBaseCmd_AfterApplyAmtInfoDegradedPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	amtCommand.EXPECT().Close().Return(nil)

	cmd := &AMTBaseCmd{SkipWSMANSetup: true}
	err := cmd.afterApply(amtCommand, false, "amd64", func(time.Duration) {})

	require.NoError(t, err)
	assert.Equal(t, -1, cmd.ControlMode)
	assert.False(t, cmd.HECIAvailable)
	assert.True(t, cmd.afterApplied)
}

func TestAMTBaseCmd_AfterApplyAmtInfoPreservesProbeFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	probeErr := errors.New("ME remains busy")

	amtCommand.EXPECT().Close().Return(nil)
	amtCommand.EXPECT().GetControlMode().Return(0, probeErr).Times(4)

	cmd := &AMTBaseCmd{SkipWSMANSetup: true}
	err := cmd.afterApply(amtCommand, true, "amd64", func(time.Duration) {})

	require.NoError(t, err)
	assert.ErrorIs(t, cmd.GetHECIInitError(), probeErr)
}

func TestAMTBaseCmd_AfterApplyPermanentErrorsAreClassifiedWithoutRetry(t *testing.T) {
	tests := []struct {
		name     string
		cause    error
		wantCode utils.CustomError
	}{
		{name: "missing device", cause: heci.ErrDeviceNotFound, wantCode: utils.HECIDriverNotDetected},
		{name: "unsupported device", cause: heci.ErrUnsupportedDevice, wantCode: utils.AmtNotDetected},
		{name: "permission denied", cause: heci.ErrPermissionDenied, wantCode: utils.IncorrectPermissions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			amtCommand := mock.NewMockInterface(ctrl)
			amtCommand.EXPECT().Close().Return(nil)
			amtCommand.EXPECT().GetControlMode().Return(0, tt.cause).Times(1)

			cmd := &AMTBaseCmd{}
			err := cmd.afterApply(amtCommand, true, "amd64", func(time.Duration) { t.Fatal("permanent errors should not retry") })

			var exitError utils.CustomError
			require.ErrorAs(t, err, &exitError)
			assert.Equal(t, tt.wantCode, exitError)
			assert.ErrorIs(t, err, tt.cause)
		})
	}
}

func TestAMTBaseCmd_AfterApplyRetryExhaustionUsesDefaultClassification(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	amtCommand.EXPECT().Close().Return(nil)

	transientErr := errors.New("ME remains busy")

	amtCommand.EXPECT().GetControlMode().Return(0, transientErr).Times(4)

	cmd := &AMTBaseCmd{}
	sleeps := 0
	err := cmd.afterApply(amtCommand, true, "amd64", func(time.Duration) { sleeps++ })

	var exitError utils.CustomError
	require.ErrorAs(t, err, &exitError)
	assert.Equal(t, utils.HECIDriverNotDetected, exitError)
	assert.ErrorIs(t, err, transientErr)
	assert.Equal(t, 3, sleeps)
}

func TestAMTBaseCmd_AfterApplyRetriesTransientError(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	amtCommand.EXPECT().Close().Return(nil)
	gomock.InOrder(
		amtCommand.EXPECT().GetControlMode().Return(0, errors.New("ME busy")),
		amtCommand.EXPECT().GetControlMode().Return(0, errors.New("ME busy")),
		amtCommand.EXPECT().GetControlMode().Return(1, nil),
	)
	amtCommand.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), nil)

	sleeps := 0
	cmd := &AMTBaseCmd{}
	err := cmd.afterApply(amtCommand, true, "amd64", func(time.Duration) { sleeps++ })

	require.NoError(t, err)
	assert.Equal(t, 2, sleeps)
	assert.Equal(t, 1, cmd.ControlMode)
	assert.True(t, cmd.HECIAvailable)
}

func TestAMTBaseCmd_AfterApplyUnsupportedArchitecture(t *testing.T) {
	tests := []struct {
		name        string
		skipWSMAN   bool
		wantErr     error
		wantInitErr error
		wantApplied bool
	}{
		{name: "AMT command reports missing driver", wantErr: utils.HECIDriverNotDetected},
		{name: "amtinfo remains degraded", skipWSMAN: true, wantInitErr: heci.ErrUnsupportedDevice, wantApplied: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			amtCommand := mock.NewMockInterface(ctrl)
			amtCommand.EXPECT().Close().Return(nil)

			cmd := &AMTBaseCmd{SkipWSMANSetup: tt.skipWSMAN}
			err := cmd.afterApply(amtCommand, true, "arm64", func(time.Duration) {})

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantApplied, cmd.afterApplied)
			assert.Equal(t, -1, cmd.ControlMode)
			assert.False(t, cmd.HECIAvailable)

			if tt.wantInitErr != nil {
				assert.ErrorIs(t, cmd.GetHECIInitError(), tt.wantInitErr)
			}
		})
	}
}
