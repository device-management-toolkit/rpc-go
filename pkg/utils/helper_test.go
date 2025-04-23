/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupEnvOrString_Default(t *testing.T) {
	result := LookupEnv("URL")
	assert.Equal(t, "", result)
}

func TestInterpretControlMode(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"Mode0", 0, "pre-provisioning state"},
		{"Mode1", 1, "activated in client control mode"},
		{"Mode2", 2, "activated in admin control mode"},
		{"Mode3", 3, "unknown state"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InterpretControlMode(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterpretHashAlgorithm(t *testing.T) {
	tests := []struct {
		name         string
		input        int
		expectedAlg  string
		expectedSize int
	}{
		{"Hash0", 0, "MD5", 16},
		{"Hash1", 1, "SHA1", 20},
		{"Hash2", 2, "SHA256", 32},
		{"Hash3", 3, "SHA512", 64},
		{"Hash4", 4, "UNKNOWN", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, alg := InterpretHashAlgorithm(tt.input)
			assert.Equal(t, tt.expectedAlg, alg)
			assert.Equal(t, tt.expectedSize, size)
		})
	}
}

func TestInterpretRemoteAccessTrigger(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"Trigger0", 0, "user initiated"},
		{"Trigger1", 1, "alert"},
		{"Trigger2", 2, "periodic"},
		{"Trigger3", 3, "provisioning"},
		{"Trigger4", 4, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InterpretRemoteAccessTrigger(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterpretAMTNetworkConnectionStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"Status0", 0, "direct"},
		{"Status1", 1, "vpn"},
		{"Status2", 2, "outside enterprise"},
		{"Status3", 3, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InterpretAMTNetworkConnectionStatus(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterpretRemoteAccessConnectionStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"ConnStatus0", 0, "not connected"},
		{"ConnStatus1", 1, "connecting"},
		{"ConnStatus2", 2, "connected"},
		{"ConnStatus3", 3, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InterpretRemoteAccessConnectionStatus(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateMPSPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		// Valid passwords
		{"ValidAllRequirements", "P@ssw0rd!", false},
		{"ValidWith16Chars", "Aa1!Aa1!Aa1!Aa1!", false},
		{"ValidMinLength", "A1a!a2B#", false},

		// Invalid due to length
		{"TooShort", "A1a!", true},
		{"TooLong", "A1a!A1a!A1a!A1a!A", true},

		// Invalid due to missing character types
		{"MissingUppercase", "p@ssw0rd", true},
		{"MissingLowercase", "P@SSW0RD", true},
		{"MissingDigit", "P@ssword", true},
		{"MissingSpecial", "Passw0rd", true},

		// Edge case: exactly one missing type
		{"OnlyUppercase", "PASSWORD", true},
		{"OnlyLowercase", "password", true},
		{"OnlyDigits", "12345678", true},
		{"OnlySpecial", "!@#$%^&*", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMPSPassword(tt.password)
			if tt.expectError {
				assert.True(t, errors.Is(err, IncorrectCommandLineParameters), "expected IncorrectCommandLineParameters error")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
