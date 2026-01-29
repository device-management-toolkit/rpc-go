/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package diagnostics

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockFlogAMTCommand is a minimal mock for testing FLOG functionality
// Only GetFlog() is actually used; other methods are stubs to satisfy amt.Interface
type MockFlogAMTCommand struct {
	mock.Mock
}

// GetFlog is the method being tested
func (m *MockFlogAMTCommand) GetFlog() ([]byte, error) {
	args := m.Called()

	return args.Get(0).([]byte), args.Error(1)
}

// Stub implementations below - required by amt.Interface but not used in these tests
func (m *MockFlogAMTCommand) Initialize() error                                    { return nil }
func (m *MockFlogAMTCommand) GetChangeEnabled() (amt.ChangeEnabledResponse, error) { return 0, nil }
func (m *MockFlogAMTCommand) EnableAMT() error                                     { return nil }
func (m *MockFlogAMTCommand) DisableAMT() error                                    { return nil }
func (m *MockFlogAMTCommand) GetVersionDataFromME(key string, timeout time.Duration) (string, error) {
	return "", nil
}
func (m *MockFlogAMTCommand) GetUUID() (string, error)                           { return "", nil }
func (m *MockFlogAMTCommand) GetControlMode() (int, error)                       { return 0, nil }
func (m *MockFlogAMTCommand) GetProvisioningState() (int, error)                 { return 0, nil }
func (m *MockFlogAMTCommand) GetOSDNSSuffix() (string, error)                    { return "", nil }
func (m *MockFlogAMTCommand) GetDNSSuffix() (string, error)                      { return "", nil }
func (m *MockFlogAMTCommand) GetCertificateHashes() ([]amt.CertHashEntry, error) { return nil, nil }
func (m *MockFlogAMTCommand) GetRemoteAccessConnectionStatus() (amt.RemoteAccessStatus, error) {
	return amt.RemoteAccessStatus{}, nil
}

func (m *MockFlogAMTCommand) GetLANInterfaceSettings(useWireless bool) (amt.InterfaceSettings, error) {
	return amt.InterfaceSettings{}, nil
}

func (m *MockFlogAMTCommand) GetLocalSystemAccount() (amt.LocalSystemAccount, error) {
	return amt.LocalSystemAccount{}, nil
}
func (m *MockFlogAMTCommand) Unprovision() (int, error) { return 0, nil }
func (m *MockFlogAMTCommand) StartConfigurationHBased(params amt.SecureHBasedParameters) (amt.SecureHBasedResponse, error) {
	return amt.SecureHBasedResponse{}, nil
}

func (m *MockFlogAMTCommand) StopConfiguration() (amt.StopConfigurationResponse, error) {
	return amt.StopConfigurationResponse{}, nil
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

	// Create context
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// Execute command
	err := cmd.Run(ctx)
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

	// Create context
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// Execute command
	err := cmd.Run(ctx)
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

	// Create context
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// Execute command - should return error
	err := cmd.Run(ctx)
	assert.Error(t, err)

	// Verify file was not created
	_, statErr := os.Stat(outputFile)
	assert.True(t, os.IsNotExist(statErr))

	mockAMT.AssertExpectations(t)
}
