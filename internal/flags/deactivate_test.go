/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleDeactivateCommandNoFlags(t *testing.T) {
	args := []string{"./rpc", "deactivate"}
	flags := NewFlags(args, MockPRSuccess)
	flags.AmtCommand.PTHI = MockPTHICommands{}
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.IncorrectCommandLineParameters)
}

func TestHandleDeactivateInvalidFlag(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-x"}

	flags := NewFlags(args, MockPRSuccess)
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.IncorrectCommandLineParameters)
}

func TestHandleDeactivateCommandNoPasswordPrompt(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost"}
	flags := NewFlags(args, MockPRSuccess)
	success := flags.ParseFlags()
	assert.EqualValues(t, success, nil)
	assert.Equal(t, utils.CommandDeactivate, flags.Command)
	assert.Equal(t, utils.TestPassword, flags.Password)
}

func TestHandleDeactivateCommandNoPasswordPromptEmpy(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost"}
	flags := NewFlags(args, MockPRFail)
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.MissingOrIncorrectPassword)
}

func TestHandleDeactivateCommandNoURL(t *testing.T) {
	args := []string{"./rpc", "deactivate", "--password", "password"}

	flags := NewFlags(args, MockPRSuccess)
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.MissingOrIncorrectURL)
}

func TestHandleDeactivateCommand(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password"}
	expected := utils.CommandDeactivate
	flags := NewFlags(args, MockPRSuccess)
	success := flags.ParseFlags()
	assert.EqualValues(t, success, nil)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, expected, flags.Command)
}

func TestHandleDeactivateCommandWithURLAndLocal(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password", "-local"}
	flags := NewFlags(args, MockPRSuccess)
	success := flags.handleDeactivateCommand()
	assert.EqualValues(t, success, utils.InvalidParameterCombination)
	assert.Equal(t, "wss://localhost", flags.URL)
}

func TestHandleDeactivateCommandWithForce(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-u", "wss://localhost", "--password", "password", "-f"}
	expected := utils.CommandDeactivate
	flags := NewFlags(args, MockPRSuccess)
	success := flags.ParseFlags()
	assert.EqualValues(t, success, nil)
	assert.Equal(t, "wss://localhost", flags.URL)
	assert.Equal(t, true, flags.Force)
	assert.Equal(t, expected, flags.Command)
}

func TestHandleLocalDeactivationWithPassword(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-local", "--password", "p@ssword"}
	flags := NewFlags(args, MockPRSuccess)
	errCode := flags.ParseFlags()
	assert.Equal(t, errCode, nil)
}

func TestHandleLocalDeactivationWithoutPassword(t *testing.T) {
	args := []string{"./rpc", "deactivate", "-local"}
	flags := NewFlags(args, MockPRSuccess)
	rc := flags.ParseFlags()
	assert.Equal(t, rc, nil)
}

func TestParseFlagsDeactivate(t *testing.T) {
	args := []string{"./rpc", "deactivate"}
	flags := NewFlags(args, MockPRSuccess)
	result := flags.ParseFlags()
	assert.EqualValues(t, result, utils.IncorrectCommandLineParameters)
	assert.Equal(t, utils.CommandDeactivate, flags.Command)
}

// Test profile loading for local deactivation
func TestHandleLocalDeactivateWithConfigV2Flags(t *testing.T) {
	// Test that configv2 and configencryptionkey flags are recognized
	args := []string{"./rpc", "deactivate", "-local", "-n", "-configv2", "profile.yaml", "-configencryptionkey", "testkey12345678901234567890123"}
	flags := NewFlags(args, MockPRSuccess)
	flags.AmtCommand.PTHI = MockPTHICommands{}

	// This should fail because the file doesn't exist, but it shows the flags are recognized
	result := flags.handleDeactivateCommand()
	// We expect an error because the file doesn't exist
	assert.NotNil(t, result)
	// But the flags should be set
	assert.Equal(t, "profile.yaml", flags.configContentV2)
	assert.Equal(t, "testkey12345678901234567890123", flags.configV2Key)
}

func TestHandleLocalDeactivateWithoutProfile(t *testing.T) {
	// Test that deactivation works without profile (CCM mode)
	args := []string{"./rpc", "deactivate", "-local", "-n"}
	flags := NewFlags(args, MockPRSuccess)
	flags.AmtCommand.PTHI = MockPTHICommands{}

	result := flags.handleDeactivateCommand()
	assert.Nil(t, result)
	assert.Equal(t, "", flags.configContentV2)
	assert.Equal(t, "", flags.LocalConfig.ACMSettings.ProvisioningCert)
}

func TestHandleLocalDeactivateConfigV2WithoutKey(t *testing.T) {
	// Test that providing configv2 without key fails
	args := []string{"./rpc", "deactivate", "-local", "-n", "-configv2", "profile.yaml"}
	flags := NewFlags(args, MockPRSuccess)
	flags.AmtCommand.PTHI = MockPTHICommands{}

	result := flags.handleDeactivateCommand()
	assert.EqualValues(t, utils.FailedReadingConfiguration, result)
}
