/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestDeactivation(t *testing.T) {
	f := flags.NewFlags(nil, MockPRSuccess)
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	stdErr := errors.New("yep it failed")

	t.Run("returns AMTConnectionFailed when GetControlMode fails", func(t *testing.T) {
		lps := setupService(f)
		mockControlModeErr = stdErr
		err := lps.Deactivate()
		assert.Equal(t, utils.AMTConnectionFailed, err)

		mockControlModeErr = nil
	})

	t.Run("returns UnableToDeactivate when ControlMode is pre-provisioning (0)", func(t *testing.T) {
		f2 := flags.NewFlags(nil, MockPRFail)
		f2.Command = utils.CommandDeactivate
		lps := setupService(f2)
		err := lps.Deactivate()
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

func TestDeactivateCCM(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	mockControlMode = 1

	t.Run("returns Success without password", func(t *testing.T) {
		f.Password = ""
		lps := setupService(f)
		err := lps.Deactivate()
		assert.NoError(t, err)
	})
	t.Run("returns Success with warning, given the password", func(t *testing.T) {
		f.Password = "P@ssw0rd"
		lps := setupService(f)
		err := lps.Deactivate()
		assert.NoError(t, err)
	})
	t.Run("returns DeactivationFailed when unprovision fails", func(t *testing.T) {
		mockUnprovisionErr = errors.New("test error")
		lps := setupService(f)
		err := lps.Deactivate()
		assert.Error(t, err)

		mockUnprovisionErr = nil
	})
	t.Run("returns DeactivationFailed when unprovision ReturnStatus is not success (0)", func(t *testing.T) {
		mockUnprovisionCode = 1
		lps := setupService(f)
		err := lps.Deactivate()
		assert.Error(t, err)

		mockUnprovisionCode = 0
	})
}

func TestDeactivateACM(t *testing.T) {
	f := flags.NewFlags(nil, MockPRFail)
	f.Command = utils.CommandDeactivate
	f.LocalConfig.Password = "P@ssw0rd"
	mockControlMode = 2

	t.Run("returns Success for happy path", func(t *testing.T) {
		f.Password = "P@ssw0rd"
		lps := setupService(f)
		err := lps.Deactivate()
		assert.NoError(t, err)
	})
	t.Run("returns UnableToDeactivate with no password", func(t *testing.T) {
		f.Password = ""
		lps := setupService(f)
		err := lps.Deactivate()
		assert.Error(t, err)
	})

	t.Run("returns UnableToDeactivate on SetupAndConfigurationService.Unprovision server error", func(t *testing.T) {
		f.Password = "P@ssw0rd"
		mockACMUnprovisionErr = errors.New("yep, it failed")
		lps := setupService(f)
		err := lps.Deactivate()
		assert.Error(t, err)

		mockACMUnprovisionErr = nil
	})
}
