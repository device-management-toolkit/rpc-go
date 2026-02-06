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

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestCIRACommand_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a temporary directory for test output
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "test_cira.txt")

	// Mock CIRA log data with valid response
	mockCiraResponse := pthi.GetCiraLogResponse{
		Header:  pthi.ResponseMessageHeader{},
		Version: 1,
		CiraStatusSummary: pthi.CIRAStatusSummary{
			IsTunnelOpened:         1,
			CurrentConnectionState: 2,
		},
	}

	// Setup mock
	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetCiraLog().Return(mockCiraResponse, nil)

	// Create command
	cmd := CIRACmd{
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

	// Verify file contains expected content
	fileData, err := os.ReadFile(outputFile)
	assert.NoError(t, err)
	assert.Contains(t, string(fileData), "Status = 0")
	assert.Contains(t, string(fileData), "Version = 1")
}

func TestCIRACommand_JSONOutput(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a temporary directory for test output
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "test_cira_json.txt")

	// Mock CIRA log data
	mockCiraResponse := pthi.GetCiraLogResponse{
		Header:  pthi.ResponseMessageHeader{},
		Version: 1,
		CiraStatusSummary: pthi.CIRAStatusSummary{
			IsTunnelOpened:         1,
			CurrentConnectionState: 2,
		},
	}

	// Setup mock
	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetCiraLog().Return(mockCiraResponse, nil)

	// Create command
	cmd := CIRACmd{
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

func TestCIRACommand_GetCiraLogError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a temporary directory for test output (even though error occurs before writing)
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "test_cira_error.txt")

	// Setup mock to return error
	mockAMT := mock.NewMockInterface(ctrl)
	expectedErr := errors.New("failed to retrieve CIRA log")
	mockAMT.EXPECT().GetCiraLog().Return(pthi.GetCiraLogResponse{}, expectedErr)

	// Create command
	cmd := CIRACmd{
		Output: outputFile,
	}

	// Create context
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// Execute command - should return error
	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve CIRA log")
}

func TestCIRACommand_EmptyResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a temporary directory for test output
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "test_cira_empty.txt")

	// Mock empty CIRA log response
	mockCiraResponse := pthi.GetCiraLogResponse{}

	// Setup mock
	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetCiraLog().Return(mockCiraResponse, nil)

	// Create command
	cmd := CIRACmd{
		Output: outputFile,
	}

	// Create context
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	// Execute command - should handle empty response
	err := cmd.Run(ctx)
	assert.NoError(t, err)

	// Verify file was created
	assert.FileExists(t, outputFile)
}
