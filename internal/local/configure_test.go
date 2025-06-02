/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestConfigure(t *testing.T) {
	f := &flags.Flags{}

	t.Run("expect success for SubCommandChangeAMTPassword", func(t *testing.T) {
		f.SubCommand = utils.SubCommandChangeAMTPassword
		f.ControlMode = 1
		lps := setupService(f)
		err := lps.Configure()
		assert.Nil(t, err)
	})
	t.Run("returns UnableToConfigure when device is not activated", func(t *testing.T) {
		f.ControlMode = 0
		lps := setupService(f)
		err := lps.Configure()
		assert.Error(t, utils.UnableToConfigure, err)

		f.ControlMode = 1
	})
	t.Run("expect error for unhandled Subcommand", func(t *testing.T) {
		customFlag := &flags.Flags{}
		customFlag.ControlMode = 1
		lps := setupService(customFlag)
		err := lps.Configure()
		assert.Equal(t, utils.IncorrectCommandLineParameters, err)
	})
	t.Run("expect error for SubCommandWireless", func(t *testing.T) {
		f.SubCommand = utils.SubCommandWireless
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.Configure()
		assert.Error(t, err)

		errEnableWiFi = nil
	})
	t.Run("expect success for SubCommandWireless", func(t *testing.T) {
		f.SubCommand = utils.SubCommandWireless
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
	})

	// Test Deprecated SubCommand addwifisettings
	t.Run("expect error for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandAddWifiSettings
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.Configure()
		assert.Error(t, err)

		errEnableWiFi = nil
	})

	// Test Deprecated SubCommand addwifisettings
	t.Run("expect success for SubCommandAddWifiSettings", func(t *testing.T) {
		f.SubCommand = utils.SubCommandAddWifiSettings
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
	})

	t.Run("expect error for SubCommandEnableWifiPort", func(t *testing.T) {
		f.SubCommand = utils.SubCommandEnableWifiPort
		errEnableWiFi = errTestError
		lps := setupService(f)
		err := lps.Configure()
		assert.Error(t, err)

		errEnableWiFi = nil
	})
	t.Run("expect success for SubCommandEnableWifiPort", func(t *testing.T) {
		f.SubCommand = utils.SubCommandEnableWifiPort
		lps := setupService(f)
		err := lps.Configure()
		assert.NoError(t, err)
	})
	t.Run("expect error for SetMebx if device is activated in client mode", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSetMEBx
		lps := setupService(f)
		mockSetupAndConfigurationErr = errTestError
		err := lps.Configure()
		assert.Error(t, utils.UnableToConfigure, err)

		mockSetupAndConfigurationErr = nil
		f.ControlMode = 2
	})
	t.Run("expect error for SetMebx", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSetMEBx
		lps := setupService(f)
		mockSetupAndConfigurationErr = errTestError
		err := lps.Configure()
		assert.Error(t, err)

		mockSetupAndConfigurationErr = nil
	})
	t.Run("expect success for SetMebx", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSetMEBx
		lps := setupService(f)
		f.ControlMode = 2
		err := lps.Configure()
		assert.NoError(t, err)
	})
	t.Run("expect error for Syncclock", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSyncClock
		lps := setupService(f)
		mockGetLowAccuracyTimeSynchErr = errTestError
		err := lps.Configure()
		assert.Error(t, err)

		mockGetLowAccuracyTimeSynchErr = nil
	})
	t.Run("expect success for Syncclock", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSyncClock
		lps := setupService(f)
		f.ControlMode = 2
		err := lps.Configure()
		assert.NoError(t, err)
	})
	t.Run("expect error for AMT features if device is activated in client mode", func(t *testing.T) {
		f.ControlMode = 1
		f.SubCommand = utils.SubCommandSetAMTFeatures
		lps := setupService(f)
		err := lps.Configure()
		assert.Error(t, utils.UnableToConfigure, err)

		f.ControlMode = 2
	})
	t.Run("expect error for AMT features", func(t *testing.T) {
		f.SubCommand = utils.SubCommandSetAMTFeatures
		lps := setupService(f)
		mockGetRedirectionServiceError = errTestError
		mockSetupAndConfigurationErr = errTestError
		err := lps.Configure()
		assert.Error(t, err)
	})
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "Valid http URL",
			url:     "http://example.com",
			wantErr: false,
		},
		{
			name:    "Valid https URL",
			url:     "https://example.com",
			wantErr: false,
		},
		{
			name:    "Missing scheme",
			url:     "://example.com",
			wantErr: true,
		},
		{
			name:    "Missing host",
			url:     "http://",
			wantErr: true,
		},
		{
			name:    "Invalid URL",
			url:     "ht!tp://[::1]/",
			wantErr: true,
		},
		{
			name:    "Relative URL without scheme and host",
			url:     "/path/to/resource",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f)
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman

			err := service.ValidateURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err, "ValidateURL() should return an error")
			} else {
				assert.NoError(t, err, "ValidateURL() should not return an error")
			}
		})
	}
}
