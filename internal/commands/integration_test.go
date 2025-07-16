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
			AMTBaseCmd: AMTBaseCmd{Password: "test-password"},
			Local:      true,
		}

		// Test that password is accessible
		assert.Equal(t, "test-password", cmd.GetPassword())

		// Test that password requirement logic works
		assert.True(t, cmd.RequiresAMTPassword(), "Local deactivate should require password")

		// Test with non-local mode
		cmd.Local = false
		assert.False(t, cmd.RequiresAMTPassword(), "Remote deactivate should not require password")
	})

	t.Run("AmtInfoCmd conditional password requirements", func(t *testing.T) {
		cmd := &AmtInfoCmd{
			AMTBaseCmd: AMTBaseCmd{Password: "test-password"},
		}

		// Test that password is accessible
		assert.Equal(t, "test-password", cmd.GetPassword())

		// Test password requirement logic
		assert.False(t, cmd.RequiresAMTPassword(), "amtinfo without user certs should not require password")

		// Test with user certificates
		cmd.UserCert = true
		assert.True(t, cmd.RequiresAMTPassword(), "amtinfo with user certs should require password")

		// Test with All flag (includes user certs)
		cmd.UserCert = false
		cmd.All = true
		assert.True(t, cmd.RequiresAMTPassword(), "amtinfo with --all should require password")
	})

	t.Run("Base command provides common functionality", func(t *testing.T) {
		cmd := &AMTBaseCmd{Password: "shared-password"}

		// Test getter method
		assert.Equal(t, "shared-password", cmd.GetPassword())

		// Test default password requirement
		assert.True(t, cmd.RequiresAMTPassword(), "Base command should require password by default")

		// Test WSMAN client getter (should be nil initially)
		assert.Nil(t, cmd.GetWSManClient())
	})
}
