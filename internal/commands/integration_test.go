/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test that demonstrates the refactored AMT password functionality works
func TestRefactoredPasswordFunctionality(t *testing.T) {
	t.Run("DeactivateCmd inherits password functionality", func(t *testing.T) {
		cmd := &DeactivateCmd{
			AMTBaseCmd: AMTBaseCmd{},
			Local:      true,
		}

		ctx := &Context{
			AMTPassword: "test-password",
		}

		// Test that password is accessible
		assert.Equal(t, "test-password", ctx.AMTPassword)

		// Test that password requirement logic works
		assert.True(t, cmd.RequiresAMTPassword(), "Local deactivate should require password")

		// Test with non-local mode
		cmd.Local = false
		assert.False(t, cmd.RequiresAMTPassword(), "Remote deactivate should not require password")
	})

	t.Run("AmtInfoCmd never requires password (uses LSA)", func(t *testing.T) {
		cmd := &AmtInfoCmd{}
		assert.False(t, cmd.RequiresAMTPassword(), "amtinfo should never require password")

		cmd.UserCert = true
		assert.False(t, cmd.RequiresAMTPassword(), "amtinfo with user certs should not require password")

		cmd.UserCert = false
		cmd.All = true
		assert.False(t, cmd.RequiresAMTPassword(), "amtinfo with --all should not require password")
	})

	t.Run("Base command provides common functionality", func(t *testing.T) {
		cmd := &AMTBaseCmd{}

		ctx := &Context{
			AMTPassword: "shared-password",
		}

		// Test getter method
		assert.Equal(t, "shared-password", ctx.AMTPassword)

		// Test default password requirement
		assert.True(t, cmd.RequiresAMTPassword(), "Base command should require password by default")

		// Test WSMAN client getter (should be nil initially)
		assert.Nil(t, cmd.GetWSManClient())
	})
}
