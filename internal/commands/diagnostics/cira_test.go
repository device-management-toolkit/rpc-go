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

func TestCIRACommand_BinaryParsingValidation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a temporary directory for test output
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "test_cira_parsing.txt")

	// Mock CIRA log response with realistic parsed data
	mockCiraResponse := pthi.GetCiraLogResponse{
		Header: pthi.ResponseMessageHeader{
			Header: pthi.MessageHeader{
				Version:  pthi.Version{MajorNumber: 1, MinorNumber: 0},
				Reserved: 0,
				Command:  pthi.CommandFormat{Val: 0x0400008e},
				Length:   2785,
			},
			Status: 0,
		},
		Version: 0,
		CiraStatusSummary: pthi.CIRAStatusSummary{
			IsTunnelOpened:            0,
			CurrentConnectionState:    2,
			LastKeepAlive:             0,
			KeepAliveInterval:         0,
			LastConnectionStatus:      1,
			LastConnectionTimestamp:   1770811569,
			LastTunnelStatus:          1,
			LastTunnelOpenedTimestamp: 1770211104,
			LastTunnelClosedTimestamp: 1770317849,
		},
		LastFailedTunnelLogEntry: pthi.CIRATunnelLogEntry{
			Valid:                         1,
			OpenTimestamp:                 1770211104,
			RemoteAccessConnectionTrigger: 2,
			MpsHostname: pthi.AMTANSIString{
				Length: 15,
				Buffer: [1000]uint8{'m', 'p', 's', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			},
			ProxyUsed:            0,
			AuthenticationMethod: 1,
			ConnectedInterface:   1,
			LastKeepAlive:        1770296249,
			KeepAliveInterval:    21600,
			TunnelClosureInfo: pthi.TunnelClosureInfo{
				ClosureTimestamp:      1770317849,
				ClosedByMps:           0,
				APF_DISCONNECT_REASON: 16,
				ClosureReason:         3,
			},
		},
		FailedConnectionLogEntry: pthi.CIRAFailedConnectionLogEntry{
			Valid:                         1,
			OpenTimestamp:                 1770811569,
			RemoteAccessConnectionTrigger: 2,
			MpsHostname: pthi.AMTANSIString{
				Length: 15,
				Buffer: [1000]uint8{'m', 'p', 's', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
			},
			AuthenticationMethod: 1,
			WirelessAdditionalData: pthi.WirelessAdditionalData{
				ProfileName: [33]byte{'W', 'I', 'F', 'I', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E', '_', '1'},
				HostControl: 1,
			},
			ConnectedInterface: 2, // INTERFACE_TYPE_NONE
			ConnectionDetails: [2]pthi.ConnectionDetail{
				{
					ConnectionStatus: 2, // DNS error - validated as uint32 (4 bytes)
					ProxyUsed:        0,
					TcpFailureCode:   0, // Validated as uint32 (4 bytes)
					TlsFailureCode:   0, // Validated as int32 (4 bytes)
				},
				{
					ConnectionStatus: 2, // DNS error - validated as uint32 (4 bytes)
					ProxyUsed:        0,
					TcpFailureCode:   0, // Validated as uint32 (4 bytes)
					TlsFailureCode:   0, // Validated as int32 (4 bytes)
				},
			},
			TunnelEstablishmentFailure: pthi.TunnelClosureInfo{
				ClosureTimestamp:      0, // Validates correct offset after ConnectionDetails array
				ClosedByMps:           0,
				APF_DISCONNECT_REASON: 0,
				ClosureReason:         0,
			},
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

	// Validate parsed response structure
	assert.Equal(t, uint8(0), mockCiraResponse.Version, "Version should be 0")
	assert.Equal(t, uint8(0), mockCiraResponse.CiraStatusSummary.IsTunnelOpened, "Tunnel should be closed")
	assert.Equal(t, uint8(2), mockCiraResponse.CiraStatusSummary.CurrentConnectionState, "Should be Outside Enterprise")
	assert.Equal(t, uint8(1), mockCiraResponse.CiraStatusSummary.LastConnectionStatus, "Last connection should have failed")
	assert.Equal(t, uint8(1), mockCiraResponse.CiraStatusSummary.LastTunnelStatus, "Last tunnel should have failed")

	// Validate LastFailedTunnelLogEntry fields
	assert.Equal(t, uint8(1), mockCiraResponse.LastFailedTunnelLogEntry.Valid, "Entry should be valid")
	assert.Equal(t, uint32(1770211104), mockCiraResponse.LastFailedTunnelLogEntry.OpenTimestamp, "OpenTimestamp should match")
	assert.Equal(t, uint8(2), mockCiraResponse.LastFailedTunnelLogEntry.RemoteAccessConnectionTrigger, "Should be Periodic trigger")
	assert.Equal(t, uint8(1), mockCiraResponse.LastFailedTunnelLogEntry.AuthenticationMethod, "Should be MutualTLS")
	assert.Equal(t, uint8(1), mockCiraResponse.LastFailedTunnelLogEntry.ConnectedInterface, "Should be WIRELESS")
	assert.Equal(t, uint32(1770317849), mockCiraResponse.LastFailedTunnelLogEntry.TunnelClosureInfo.ClosureTimestamp, "Tunnel closure timestamp should match")

	// Validate FailedConnectionLogEntry fields
	assert.Equal(t, uint8(1), mockCiraResponse.FailedConnectionLogEntry.Valid, "Entry should be valid")
	assert.Equal(t, uint8(1), mockCiraResponse.FailedConnectionLogEntry.AuthenticationMethod, "Should be MutualTLS")
	assert.Equal(t, uint8(2), mockCiraResponse.FailedConnectionLogEntry.ConnectedInterface, "Should be NONE")

	// Validate ConnectionDetails array entries
	assert.Equal(t, uint32(2), mockCiraResponse.FailedConnectionLogEntry.ConnectionDetails[0].ConnectionStatus, "ConnectionStatus should be uint32")
	assert.Equal(t, uint32(0), mockCiraResponse.FailedConnectionLogEntry.ConnectionDetails[0].TcpFailureCode, "TcpFailureCode should be uint32")
	assert.Equal(t, int32(0), mockCiraResponse.FailedConnectionLogEntry.ConnectionDetails[0].TlsFailureCode, "TlsFailureCode should be int32")

	assert.Equal(t, uint32(2), mockCiraResponse.FailedConnectionLogEntry.ConnectionDetails[1].ConnectionStatus, "ConnectionStatus should be uint32")
	assert.Equal(t, uint32(0), mockCiraResponse.FailedConnectionLogEntry.ConnectionDetails[1].TcpFailureCode, "TcpFailureCode should be uint32")
	assert.Equal(t, int32(0), mockCiraResponse.FailedConnectionLogEntry.ConnectionDetails[1].TlsFailureCode, "TlsFailureCode should be int32")

	// Validate TunnelEstablishmentFailure fields
	assert.Equal(t, uint32(0), mockCiraResponse.FailedConnectionLogEntry.TunnelEstablishmentFailure.ClosureTimestamp, "ClosureTimestamp should be 0")
	assert.Equal(t, uint8(0), mockCiraResponse.FailedConnectionLogEntry.TunnelEstablishmentFailure.ClosedByMps, "ClosedBy should be AMT")
	assert.Equal(t, uint8(0), mockCiraResponse.FailedConnectionLogEntry.TunnelEstablishmentFailure.APF_DISCONNECT_REASON, "APF disconnect should be INVALID")
	assert.Equal(t, uint8(0), mockCiraResponse.FailedConnectionLogEntry.TunnelEstablishmentFailure.ClosureReason, "Closure reason should be USER_INITIATE")

	// Validate string field parsing
	mpsHostname := string(mockCiraResponse.FailedConnectionLogEntry.MpsHostname.Buffer[:mockCiraResponse.FailedConnectionLogEntry.MpsHostname.Length])
	assert.Equal(t, "mps.example.com", mpsHostname, "MPS hostname should be parsed correctly")

	profileName := string(mockCiraResponse.FailedConnectionLogEntry.WirelessAdditionalData.ProfileName[:14])
	assert.Equal(t, "WIFI_PROFILE_1", profileName, "Wireless profile name should be parsed correctly")

	// Verify file was created and contains expected content
	assert.FileExists(t, outputFile)
	fileData, err := os.ReadFile(outputFile)
	assert.NoError(t, err)
	assert.Contains(t, string(fileData), "Status = 0")
	assert.Contains(t, string(fileData), "ClosureTimestamp = 0")
	assert.Contains(t, string(fileData), "ConnectionStatus = 2")
	assert.Contains(t, string(fileData), "mps.example.com")
	assert.Contains(t, string(fileData), "WIFI_PROFILE_1")
}
