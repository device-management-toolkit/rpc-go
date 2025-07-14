/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAMTCommand is a mock implementation of amt.Interface
type MockAMTCommand struct {
	mock.Mock
}

func (m *MockAMTCommand) Initialize() error {
	args := m.Called()

	return args.Error(0)
}

func (m *MockAMTCommand) GetChangeEnabled() (amt.ChangeEnabledResponse, error) {
	args := m.Called()

	return args.Get(0).(amt.ChangeEnabledResponse), args.Error(1)
}

func (m *MockAMTCommand) EnableAMT() error {
	args := m.Called()

	return args.Error(0)
}

func (m *MockAMTCommand) DisableAMT() error {
	args := m.Called()

	return args.Error(0)
}

func (m *MockAMTCommand) GetVersionDataFromME(key string, amtTimeout time.Duration) (string, error) {
	args := m.Called(key, amtTimeout)

	return args.String(0), args.Error(1)
}

func (m *MockAMTCommand) GetUUID() (string, error) {
	args := m.Called()

	return args.String(0), args.Error(1)
}

func (m *MockAMTCommand) GetControlMode() (int, error) {
	args := m.Called()

	return args.Int(0), args.Error(1)
}

func (m *MockAMTCommand) GetOSDNSSuffix() (string, error) {
	args := m.Called()

	return args.String(0), args.Error(1)
}

func (m *MockAMTCommand) GetDNSSuffix() (string, error) {
	args := m.Called()

	return args.String(0), args.Error(1)
}

func (m *MockAMTCommand) GetCertificateHashes() ([]amt.CertHashEntry, error) {
	args := m.Called()

	return args.Get(0).([]amt.CertHashEntry), args.Error(1)
}

func (m *MockAMTCommand) GetRemoteAccessConnectionStatus() (amt.RemoteAccessStatus, error) {
	args := m.Called()

	return args.Get(0).(amt.RemoteAccessStatus), args.Error(1)
}

func (m *MockAMTCommand) GetLANInterfaceSettings(useWireless bool) (amt.InterfaceSettings, error) {
	args := m.Called(useWireless)

	return args.Get(0).(amt.InterfaceSettings), args.Error(1)
}

func (m *MockAMTCommand) GetLocalSystemAccount() (amt.LocalSystemAccount, error) {
	args := m.Called()

	return args.Get(0).(amt.LocalSystemAccount), args.Error(1)
}

func (m *MockAMTCommand) Unprovision() (int, error) {
	args := m.Called()

	return args.Int(0), args.Error(1)
}

func (m *MockAMTCommand) StartConfigurationHBased(params amt.SecureHBasedParameters) (amt.SecureHBasedResponse, error) {
	args := m.Called(params)

	return args.Get(0).(amt.SecureHBasedResponse), args.Error(1)
}

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		expected string
	}{
		{
			name:     "version command",
			args:     []string{"rpc", "version"},
			wantErr:  false,
			expected: "version",
		},
		{
			name:     "amtinfo command",
			args:     []string{"rpc", "amtinfo"},
			wantErr:  false,
			expected: "amtinfo",
		},
		{
			name:     "amtinfo with flags",
			args:     []string{"rpc", "amtinfo", "--ver", "--sku"},
			wantErr:  false,
			expected: "amtinfo",
		},
		// Note: Help tests are excluded because Kong calls os.Exit(0)
		// which cannot be tested in unit tests
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock AMT command for testing
			mockAMT := &MockAMTCommand{}
			ctx, cli, err := Parse(tt.args, mockAMT)

			if tt.wantErr {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, ctx)
			assert.NotNil(t, cli)

			if tt.expected != "" {
				// Check that the correct command was selected
				assert.Equal(t, tt.expected, ctx.Selected().Name)
			}
		})
	}
}

func TestGlobalsBeforeApply(t *testing.T) {
	tests := []struct {
		name    string
		globals Globals
		wantErr bool
	}{
		{
			name: "default settings",
			globals: Globals{
				LogLevel:   "info",
				JsonOutput: false,
				Verbose:    false,
			},
			wantErr: false,
		},
		{
			name: "verbose enabled",
			globals: Globals{
				LogLevel:   "info",
				JsonOutput: false,
				Verbose:    true,
			},
			wantErr: false,
		},
		{
			name: "json output enabled",
			globals: Globals{
				LogLevel:   "info",
				JsonOutput: true,
				Verbose:    false,
			},
			wantErr: false,
		},
		{
			name: "debug level",
			globals: Globals{
				LogLevel:   "debug",
				JsonOutput: false,
				Verbose:    false,
			},
			wantErr: false,
		},
		{
			name: "invalid log level",
			globals: Globals{
				LogLevel:   "invalid",
				JsonOutput: false,
				Verbose:    false,
			},
			wantErr: false, // Should not error, just warn and use default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.globals.AfterApply(nil)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
