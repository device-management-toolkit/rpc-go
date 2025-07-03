/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestKongCLIIntegration demonstrates the new Kong CLI system working
func TestKongCLIIntegration(t *testing.T) {
	mockAMT := &MockAMTCommandForIntegration{}

	// Test version command
	t.Run("version command", func(t *testing.T) {
		ctx, cli, err := Parse([]string{"rpc", "version"}, mockAMT)
		assert.NoError(t, err)
		assert.NotNil(t, ctx)
		assert.NotNil(t, cli)
		assert.Equal(t, "version", ctx.Selected().Name)
	})

	// Test amtinfo command with flags
	t.Run("amtinfo with flags", func(t *testing.T) {
		ctx, cli, err := Parse([]string{"rpc", "amtinfo", "--ver", "--sku", "--all"}, mockAMT)
		assert.NoError(t, err)
		assert.NotNil(t, ctx)
		assert.NotNil(t, cli)
		assert.Equal(t, "amtinfo", ctx.Selected().Name)
	})

	// Test global flags
	t.Run("global verbose and json flags", func(t *testing.T) {
		ctx, cli, err := Parse([]string{"rpc", "--verbose", "--json", "version"}, mockAMT)
		assert.NoError(t, err)
		assert.NotNil(t, ctx)
		assert.NotNil(t, cli)
		assert.True(t, cli.Verbose)
		assert.True(t, cli.JsonOutput)
		assert.Equal(t, "version", ctx.Selected().Name)
	})
	// Test amtinfo password flag
	t.Run("amtinfo with password", func(t *testing.T) {
		ctx, cli, err := Parse([]string{"rpc", "amtinfo", "--cert", "--password", "test123"}, mockAMT)
		assert.NoError(t, err)
		assert.NotNil(t, ctx)
		assert.NotNil(t, cli)
		assert.Equal(t, "amtinfo", ctx.Selected().Name)

		// Verify that the amtinfo command has the cert flag set
		assert.True(t, cli.AmtInfo.Cert)
		assert.Equal(t, "test123", cli.AmtInfo.Password)
	})

	// Test log level setting
	t.Run("log level setting", func(t *testing.T) {
		ctx, cli, err := Parse([]string{"rpc", "--log-level", "debug", "version"}, mockAMT)
		assert.NoError(t, err)
		assert.NotNil(t, ctx)
		assert.NotNil(t, cli)
		assert.Equal(t, "debug", cli.LogLevel)
	})
}

// TestKongCLIErrorHandling tests error conditions
func TestKongCLIErrorHandling(t *testing.T) {
	mockAMT := &MockAMTCommandForIntegration{}

	// Test invalid command
	t.Run("invalid command", func(t *testing.T) {
		_, _, err := Parse([]string{"rpc", "invalidcommand"}, mockAMT)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected argument")
	})

	// Test invalid flag
	t.Run("invalid flag", func(t *testing.T) {
		_, _, err := Parse([]string{"rpc", "version", "--invalid-flag"}, mockAMT)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown flag")
	})

	// Test no command provided
	t.Run("no command", func(t *testing.T) {
		_, _, err := Parse([]string{"rpc"}, mockAMT)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected one of")
	})
}
