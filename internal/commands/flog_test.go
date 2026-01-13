/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAMTCommand is a mock implementation of amt.Interface for testing
type MockFlogAMTCommand struct {
	mock.Mock
}

func (m *MockFlogAMTCommand) Initialize() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockFlogAMTCommand) GetChangeEnabled() (amt.ChangeEnabledResponse, error) {
	args := m.Called()
	return args.Get(0).(amt.ChangeEnabledResponse), args.Error(1)
}

func (m *MockFlogAMTCommand) EnableAMT() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockFlogAMTCommand) DisableAMT() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockFlogAMTCommand) GetVersionDataFromME(key string, timeout time.Duration) (string, error) {
	args := m.Called(key, timeout)
	return args.String(0), args.Error(1)
}

func (m *MockFlogAMTCommand) GetUUID() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockFlogAMTCommand) GetControlMode() (int, error) {
	args := m.Called()
	return args.Int(0), args.Error(1)
}

func (m *MockFlogAMTCommand) GetOSDNSSuffix() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockFlogAMTCommand) GetDNSSuffix() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockFlogAMTCommand) GetCertificateHashes() ([]amt.CertHashEntry, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]amt.CertHashEntry), args.Error(1)
}

func (m *MockFlogAMTCommand) GetRemoteAccessConnectionStatus() (amt.RemoteAccessStatus, error) {
	args := m.Called()
	return args.Get(0).(amt.RemoteAccessStatus), args.Error(1)
}

func (m *MockFlogAMTCommand) GetLANInterfaceSettings(useWireless bool) (amt.InterfaceSettings, error) {
	args := m.Called(useWireless)
	return args.Get(0).(amt.InterfaceSettings), args.Error(1)
}

func (m *MockFlogAMTCommand) GetLocalSystemAccount() (amt.LocalSystemAccount, error) {
	args := m.Called()
	return args.Get(0).(amt.LocalSystemAccount), args.Error(1)
}

func (m *MockFlogAMTCommand) Unprovision() (int, error) {
	args := m.Called()
	return args.Int(0), args.Error(1)
}

func (m *MockFlogAMTCommand) StartConfigurationHBased(params amt.SecureHBasedParameters) (amt.SecureHBasedResponse, error) {
	args := m.Called(params)
	return args.Get(0).(amt.SecureHBasedResponse), args.Error(1)
}

func (m *MockFlogAMTCommand) GetFlog() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func TestFlogCommand_Success(t *testing.T) {
	// Create a temporary directory for test output
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "test_flog.bin")

	// Mock FLOG data
	mockFlogData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Setup mock
	mockAMT := new(MockFlogAMTCommand)
	mockAMT.On("GetFlog").Return(mockFlogData, nil)

	// Create command
	cmd := FlogCmd{
		Output: outputFile,
	}

	// Execute command
	err := cmd.Run(nil, mockAMT)
	assert.NoError(t, err)

	// Verify file was created
	assert.FileExists(t, outputFile)

	// Verify file contents
	fileData, err := os.ReadFile(outputFile)
	assert.NoError(t, err)
	assert.Equal(t, mockFlogData, fileData)

	mockAMT.AssertExpectations(t)
}

func TestFlogCommand_DirectoryCreation(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "subdir", "nested", "test_flog.bin")

	// Mock FLOG data
	mockFlogData := []byte{0x01, 0x02, 0x03, 0x04}

	// Setup mock
	mockAMT := new(MockFlogAMTCommand)
	mockAMT.On("GetFlog").Return(mockFlogData, nil)

	// Create command
	cmd := FlogCmd{
		Output: outputFile,
	}

	// Execute command
	err := cmd.Run(nil, mockAMT)
	assert.NoError(t, err)

	// Verify file was created
	assert.FileExists(t, outputFile)

	mockAMT.AssertExpectations(t)
}

func TestFlogCommand_GetFlogError(t *testing.T) {
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "test_flog.bin")

	// Setup mock to return error
	mockAMT := new(MockFlogAMTCommand)
	mockAMT.On("GetFlog").Return([]byte{}, assert.AnError)

	// Create command
	cmd := FlogCmd{
		Output: outputFile,
	}

	// Execute command - should return error
	err := cmd.Run(nil, mockAMT)
	assert.Error(t, err)

	// Verify file was not created
	_, statErr := os.Stat(outputFile)
	assert.True(t, os.IsNotExist(statErr))

	mockAMT.AssertExpectations(t)
}
