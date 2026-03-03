/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestCSMECommand_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a temporary directory for test output
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "test_flog.bin")

	// Mock FLOG data
	mockFlogData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Setup mock
	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetFlog().Return(mockFlogData, nil)

	// Create command
	cmd := CSMECmd{
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
}

func TestCSMECommand_DirectoryCreation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a temporary directory
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "subdir", "nested", "test_flog.bin")

	// Mock FLOG data
	mockFlogData := []byte{0x01, 0x02, 0x03, 0x04}

	// Setup mock
	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetFlog().Return(mockFlogData, nil)

	// Create command
	cmd := CSMECmd{
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
}

func TestCSMECommand_GetFlogError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "test_flog.bin")

	// Setup mock to return error
	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetFlog().Return([]byte{}, errors.New("failed to retrieve flog"))

	// Create command
	cmd := CSMECmd{
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
}

func TestCSMECommand_DefaultFilename(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Save current directory and change to temp dir so default file is created there
	originalDir, err := os.Getwd()
	assert.NoError(t, err)

	tempDir := t.TempDir()
	err = os.Chdir(tempDir)
	assert.NoError(t, err)

	defer func() {
		_ = os.Chdir(originalDir)
	}()

	// Mock FLOG data
	mockFlogData := []byte{0x01, 0x02, 0x03, 0x04}

	// Setup mock
	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetFlog().Return(mockFlogData, nil)

	// Create command with no output specified
	cmd := CSMECmd{}

	// Create context
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// Capture time before execution
	beforeTime := time.Now()

	// Execute command
	err = cmd.Run(ctx)
	assert.NoError(t, err)

	// Verify default filename was set with expected pattern
	assert.NotEmpty(t, cmd.Output)
	assert.Contains(t, cmd.Output, "_csme_flash_log.bin")

	// Verify timestamp portion is valid (format: YYYYMMDD_HHMMSS)
	// The filename should start with a timestamp close to beforeTime
	expectedPrefix := beforeTime.Format("20060102_")
	assert.Contains(t, cmd.Output, expectedPrefix)

	// Verify file was created
	assert.FileExists(t, cmd.Output)

	// Verify file contents
	fileData, err := os.ReadFile(cmd.Output)
	assert.NoError(t, err)
	assert.Equal(t, mockFlogData, fileData)
}
