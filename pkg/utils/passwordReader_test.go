/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// MockPasswordReaderForTest implements PasswordReader for testing
type MockPasswordReaderForTest struct {
	passwords []string
	index     int
	err       error
}

func (m *MockPasswordReaderForTest) ReadPassword() (string, error) {
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

func (m *MockPasswordReaderForTest) ReadPasswordWithConfirmation(prompt, confirmPrompt string) (string, error) {
	if m.err != nil {
		return "", m.err
	}

	if len(m.passwords) < 2 {
		if len(m.passwords) == 1 {
			return m.passwords[0], nil
		}

		return "", nil
	}

	pw1 := m.passwords[0]
	pw2 := m.passwords[1]
	m.index = 2

	if pw1 != pw2 {
		return "", PasswordsDoNotMatch
	}

	return pw1, nil
}

func TestReadPasswordWithConfirmation_MatchingPasswords(t *testing.T) {
	original := PR

	defer func() { PR = original }()

	PR = &MockPasswordReaderForTest{passwords: []string{"SecurePass123!", "SecurePass123!"}}

	pw, err := PR.ReadPasswordWithConfirmation("Password: ", "Confirm: ")
	assert.NoError(t, err)
	assert.Equal(t, "SecurePass123!", pw)
}

func TestReadPasswordWithConfirmation_MismatchingPasswords(t *testing.T) {
	original := PR

	defer func() { PR = original }()

	PR = &MockPasswordReaderForTest{passwords: []string{"Password1!", "Password2!"}}

	pw, err := PR.ReadPasswordWithConfirmation("Password: ", "Confirm: ")
	assert.Error(t, err)
	assert.ErrorIs(t, err, PasswordsDoNotMatch)
	assert.Empty(t, pw)
}

func TestReadPasswordWithConfirmation_Error(t *testing.T) {
	original := PR

	defer func() { PR = original }()

	PR = &MockPasswordReaderForTest{err: assert.AnError}

	pw, err := PR.ReadPasswordWithConfirmation("Password: ", "Confirm: ")
	assert.Error(t, err)
	assert.Empty(t, pw)
}
