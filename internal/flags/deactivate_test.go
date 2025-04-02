/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"testing"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
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
