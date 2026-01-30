//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}

	// Ensure it implements the Interface
	var _ Interface = client
}

func TestNewUPID(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "Valid UPID",
			input:   make([]byte, UPIDSize),
			wantErr: false,
		},
		{
			name:    "Invalid size - too short",
			input:   make([]byte, 32),
			wantErr: true,
		},
		{
			name:    "Invalid size - too long",
			input:   make([]byte, 128),
			wantErr: true,
		},
		{
			name:    "Empty input",
			input:   []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upid, err := NewUPID(tt.input, PlatformIDTypeBinary)
			if tt.wantErr {
				if err == nil {
					t.Error("NewUPID() expected error, got nil")
				}

				if upid != nil {
					t.Error("NewUPID() should return nil on error")
				}
			} else {
				if err != nil {
					t.Errorf("NewUPID() unexpected error: %v", err)
				}

				if upid == nil {
					t.Error("NewUPID() returned nil without error")

					return
				}

				if len(upid.Raw) != UPIDSize {
					t.Errorf("UPID.Raw size = %d, want %d", len(upid.Raw), UPIDSize)
				}

				if len(upid.OEMPlatformID) != OEMPlatformIDSize {
					t.Errorf("UPID.OEMPlatformID size = %d, want %d", len(upid.OEMPlatformID), OEMPlatformIDSize)
				}

				if len(upid.HWSerialNum) != HWSerialNumSize {
					t.Errorf("UPID.HWSerialNum size = %d, want %d", len(upid.HWSerialNum), HWSerialNumSize)
				}
			}
		})
	}
}

func TestUPIDString(t *testing.T) {
	tests := []struct {
		name     string
		upid     *UPID
		expected string
	}{
		{
			name:     "Nil UPID",
			upid:     nil,
			expected: "",
		},
		{
			name: "UPID with nil Raw",
			upid: &UPID{
				Raw: nil,
			},
			expected: "",
		},
		{
			name: "Valid UPID with zeros (OEM not provisioned, only shows CSME)",
			upid: &UPID{
				Raw:            make([]byte, UPIDSize),
				PlatformIdType: PlatformIDTypeNotSet,
			},
			expected: "---UPID---\nOEM_PLATFORM_ID_TYPE    : Not Set (0)\nOEM ID                  :\nCSME ID                 : 0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name: "Valid UPID with OEM provisioned (shows both IDs with type)",
			upid: &UPID{
				Raw: func() []byte {
					raw := make([]byte, UPIDSize)
					// Set first byte of OEM to non-zero
					raw[0] = 0xAB
					// Set some CSME bytes
					raw[32] = 0xCD
					raw[33] = 0xEF

					return raw
				}(),
				PlatformIdType: PlatformIDTypeBinary,
			},
			expected: "---UPID---\nOEM_PLATFORM_ID_TYPE    : Binary (1)\nOEM ID                  : AB00000000000000000000000000000000000000000000000000000000000000\nCSME ID                 : CDEF000000000000000000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.upid.String()
			if result != tt.expected {
				t.Errorf("UPID.String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestUPIDConstants(t *testing.T) {
	if UPIDSize != 64 {
		t.Errorf("UPIDSize = %d, want 64", UPIDSize)
	}

	if OEMPlatformIDSize != 32 {
		t.Errorf("OEMPlatformIDSize = %d, want 32", OEMPlatformIDSize)
	}

	if HWSerialNumSize != 32 {
		t.Errorf("HWSerialNumSize = %d, want 32", HWSerialNumSize)
	}
}

func TestCommandConstants(t *testing.T) {
	tests := []struct {
		name     string
		value    uint8
		expected uint8
	}{
		{"CommandFeaturePlatformID", CommandFeaturePlatformID, 0},
		{"CommandFeatureSupportGet", CommandFeatureSupportGet, 0},
		{"CommandFeatureStateGet", CommandFeatureStateGet, 1},
		{"CommandFeatureStateSet", CommandFeatureStateSet, 2},
		{"CommandFeatureStateOSControlGet", CommandFeatureStateOSControlGet, 3},
		{"CommandFeatureStateOSControlSet", CommandFeatureStateOSControlSet, 4},
		{"CommandPlatformIDGet", CommandPlatformIDGet, 5},
		{"CommandRefurbishCounterGet", CommandRefurbishCounterGet, 6},
		{"CommandOEMPlatformIDUpdate", CommandOEMPlatformIDUpdate, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.expected)
			}
		})
	}
}

func TestStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		value    uint8
		expected uint8
	}{
		{"StatusSuccess", StatusSuccess, 0},
		{"StatusFeatureNotSupported", StatusFeatureNotSupported, 1},
		{"StatusInvalidInputParameter", StatusInvalidInputParameter, 2},
		{"StatusInternalError", StatusInternalError, 3},
		{"StatusNotAllowedAfterEOP", StatusNotAllowedAfterEOP, 4},
		{"StatusNotAllowedAfterManufLock", StatusNotAllowedAfterManufLock, 5},
		{"StatusMaxCountersExceeded", StatusMaxCountersExceeded, 6},
		{"StatusInvalidState", StatusInvalidState, 7},
		{"StatusReserved2", StatusReserved2, 8},
		{"StatusNotAllowedAfterCBD", StatusNotAllowedAfterCBD, 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.expected)
			}
		})
	}
}

func TestFeatureStateConstants(t *testing.T) {
	if FeatureStateDisabled != 0 {
		t.Errorf("FeatureStateDisabled = %d, want 0", FeatureStateDisabled)
	}
	if FeatureStateEnabled != 1 {
		t.Errorf("FeatureStateEnabled = %d, want 1", FeatureStateEnabled)
	}
}

func TestPlatformIDTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		value    uint32
		expected uint32
	}{
		{"PlatformIDTypeNotSet", PlatformIDTypeNotSet, 0},
		{"PlatformIDTypeBinary", PlatformIDTypeBinary, 1},
		{"PlatformIDTypePrintableString", PlatformIDTypePrintableString, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.expected)
			}
		})
	}
}

func TestErrorDefinitions(t *testing.T) {
	errors := []error{
		ErrUPIDNotSupported,
		ErrUPIDNotEnabled,
		ErrUPIDNotProvisioned,
		ErrInvalidResponse,
		ErrConnectionFailed,
		ErrCommandFailed,
		ErrInsufficientPriv,
		ErrFeatureNotSupported,
		ErrInvalidInputParameter,
		ErrInternalError,
		ErrNotAllowedAfterEOP,
		ErrInvalidState,
		ErrNotAllowedAfterManufLock,
		ErrMaxCountersExceeded,
		ErrNotAllowedAfterCBD,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("Error constant is nil")
		}
		if err.Error() == "" {
			t.Error("Error constant has empty message")
		}
	}
}

func TestUPIDStructSize(t *testing.T) {
	upidData := make([]byte, UPIDSize)
	// Set some test data
	for i := 0; i < 32; i++ {
		upidData[i] = 0xAA // OEM part
	}
	for i := 32; i < 64; i++ {
		upidData[i] = 0xBB // CSME part
	}

	upid, err := NewUPID(upidData, PlatformIDTypeBinary)
	if err != nil {
		t.Fatalf("NewUPID() failed: %v", err)
	}

	// Verify the data is split correctly
	for i := 0; i < 32; i++ {
		if upid.OEMPlatformID[i] != 0xAA {
			t.Errorf("OEMPlatformID[%d] = 0x%02x, want 0xAA", i, upid.OEMPlatformID[i])
		}
		if upid.HWSerialNum[i] != 0xBB {
			t.Errorf("HWSerialNum[%d] = 0x%02x, want 0xBB", i, upid.HWSerialNum[i])
		}
	}

	// Verify string format
	str := upid.String()
	if len(str) == 0 {
		t.Error("UPID.String() returned empty string")
	}
}

func TestUPIDStringFormatting(t *testing.T) {
	// Create a UPID with known values
	upidData := make([]byte, 64)
	// Set OEM Platform ID bytes (bytes 0-31)
	upidData[0] = 0x12
	upidData[1] = 0x34
	// Set CSME Platform ID bytes (bytes 32-63)
	upidData[32] = 0xAB
	upidData[33] = 0xCD

	upid, err := NewUPID(upidData, PlatformIDTypePrintableString)
	if err != nil {
		t.Fatalf("NewUPID() failed: %v", err)
	}

	str := upid.String()

	// Verify the string starts with the header
	if !contains(str, "---UPID---") {
		t.Fatal("UPID string should start with ---UPID---")
	}

	// Verify CSME ID is present
	if !contains(str, "CSME ID") {
		t.Fatal("UPID string should contain CSME ID label")
	}

	// Verify hex values are uppercase
	if !contains(str, "ABCD") {
		t.Error("UPID string should contain uppercase ABCD hex values")
	}

	// Verify it contains newline and spaces for second line formatting
	if !contains(str, "\n") {
		t.Error("UPID string missing newline separator")
	}
}

func TestUPIDHECIHeaderSize(t *testing.T) {
	// Verify header is 4 bytes as per Intel spec
	var header UPIDHECIHeader
	header.Feature = 0
	header.Command = 5
	header.ByteCount = 0

	if header.Feature != 0 {
		t.Errorf("Header.Feature = %d, want 0", header.Feature)
	}
	if header.Command != 5 {
		t.Errorf("Header.Command = %d, want 5", header.Command)
	}
	if header.ByteCount != 0 {
		t.Errorf("Header.ByteCount = %d, want 0", header.ByteCount)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}

	return false
}

// MockHECI implements heci.Interface for testing
type MockHECI struct {
	initWithGUIDFunc   func(guid interface{}) error
	sendMessageFunc    func(buffer []byte, done *uint32) (int, error)
	receiveMessageFunc func(buffer []byte, done *uint32) (int, error)
	closed             bool
}

func (m *MockHECI) Init(useLME, useWD bool) error {
	return nil
}

func (m *MockHECI) InitWithGUID(guid interface{}) error {
	if m.initWithGUIDFunc != nil {
		return m.initWithGUIDFunc(guid)
	}

	return nil
}

func (m *MockHECI) InitHOTHAM() error {
	return nil
}

func (m *MockHECI) GetBufferSize() uint32 {
	return 5120
}

func (m *MockHECI) SendMessage(buffer []byte, done *uint32) (int, error) {
	if m.sendMessageFunc != nil {
		return m.sendMessageFunc(buffer, done)
	}

	return len(buffer), nil
}

func (m *MockHECI) ReceiveMessage(buffer []byte, done *uint32) (int, error) {
	if m.receiveMessageFunc != nil {
		return m.receiveMessageFunc(buffer, done)
	}

	return 0, nil
}

func (m *MockHECI) Close() {
	m.closed = true
}

// TestGetUPIDWindows tests GetUPID implementation with mock
func TestGetUPIDWindows(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(*MockHECI)
		wantErr     bool
		wantErrType error
		checkUPID   func(*testing.T, *UPID)
	}{
		{
			name: "successful UPID retrieval - OEM provisioned",
			setupMock: func(m *MockHECI) {
				callCount := 0
				m.receiveMessageFunc = func(buffer []byte, done *uint32) (int, error) {
					callCount++
					switch callCount {
					case 1:
						// First call: enable feature response (command 2)
						// Response format: [Feature|Command|ByteCount(2bytes)|Status(4bytes)]
						response := make([]byte, 8)
						response[1] = CommandFeatureStateSet
						binary.LittleEndian.PutUint32(response[4:8], uint32(StatusSuccess))
						copy(buffer, response)

						if done != nil {
							*done = uint32(len(response))
						}

						return len(response), nil
					case 2:
						// Second call: UPID response with OEM provisioned (command 5)
						// Response format: [Feature|Command|ByteCount(2bytes)|Status(4bytes)|PlatformIdType(4bytes)|OEM(32bytes)|CSME(32bytes)]
						response := make([]byte, 76)
						response[1] = CommandPlatformIDGet
						binary.LittleEndian.PutUint16(response[2:4], 72)                    // ByteCount (2 bytes)
						binary.LittleEndian.PutUint32(response[4:8], uint32(StatusSuccess)) // Status (4 bytes)
						// PlatformIdType (4 bytes at offset 8)
						binary.LittleEndian.PutUint32(response[8:12], PlatformIDTypeBinary)
						// OEM Platform ID (32 bytes at offset 12)
						for i := 0; i < 32; i++ {
							response[12+i] = 0xAA
						}

						// CSME Platform ID (32 bytes at offset 44)
						for i := 0; i < 32; i++ {
							response[44+i] = 0xBB
						}

						copy(buffer, response)

						if done != nil {
							*done = uint32(len(response))
						}

						return len(response), nil
					default:
						// Third call: disable feature response (command 2)
						response := make([]byte, 8)
						response[1] = CommandFeatureStateSet
						binary.LittleEndian.PutUint32(response[4:8], uint32(StatusSuccess))
						copy(buffer, response)

						if done != nil {
							*done = uint32(len(response))
						}

						return len(response), nil
					}
				}
			},
			wantErr: false,
			checkUPID: func(t *testing.T, upid *UPID) {
				if upid == nil {
					t.Fatal("Expected UPID, got nil")
				}
				if len(upid.Raw) != 64 {
					t.Errorf("Expected Raw length 64, got %d", len(upid.Raw))
				}
				// Verify OEM ID (bytes 0-31)
				for i := 0; i < 32; i++ {
					if upid.OEMPlatformID[i] != 0xAA {
						t.Errorf("OEMPlatformID[%d] = 0x%02x, want 0xAA", i, upid.OEMPlatformID[i])

						break
					}
				}
				// Verify CSME ID (bytes 32-63)
				for i := 0; i < 32; i++ {
					if upid.HWSerialNum[i] != 0xBB {
						t.Errorf("HWSerialNum[%d] = 0x%02x, want 0xBB", i, upid.HWSerialNum[i])

						break
					}
				}
			},
		},
		{
			name: "UPID not supported",
			setupMock: func(m *MockHECI) {
				m.initWithGUIDFunc = func(guid interface{}) error {
					return errors.New("device not found")
				}
			},
			wantErr:     true,
			wantErrType: ErrUPIDNotSupported,
		},
		{
			name: "UPID not provisioned - short response",
			setupMock: func(m *MockHECI) {
				callCount := 0
				m.receiveMessageFunc = func(buffer []byte, done *uint32) (int, error) {
					callCount++
					switch callCount {
					case 1:
						// Enable feature response
						response := make([]byte, 8)
						response[1] = CommandFeatureStateSet
						binary.LittleEndian.PutUint32(response[4:8], uint32(StatusSuccess))
						copy(buffer, response)

						if done != nil {
							*done = uint32(len(response))
						}

						return len(response), nil
					case 2:
						// Short response (8 bytes) with SUCCESS indicates not provisioned
						response := make([]byte, 8)
						response[1] = CommandPlatformIDGet
						binary.LittleEndian.PutUint16(response[2:4], 0)                     // ByteCount = 0
						binary.LittleEndian.PutUint32(response[4:8], uint32(StatusSuccess)) // Status
						copy(buffer, response)

						if done != nil {
							*done = uint32(len(response))
						}

						return len(response), nil
					default:
						// Disable feature response
						response := make([]byte, 8)
						response[1] = CommandFeatureStateSet
						binary.LittleEndian.PutUint32(response[4:8], uint32(StatusSuccess))
						copy(buffer, response)

						if done != nil {
							*done = uint32(len(response))
						}

						return len(response), nil
					}
				}
			},
			wantErr:     true,
			wantErrType: ErrUPIDNotProvisioned,
		},
		{
			name: "UPID disabled status",
			setupMock: func(m *MockHECI) {
				callCount := 0
				m.receiveMessageFunc = func(buffer []byte, done *uint32) (int, error) {
					callCount++
					switch callCount {
					case 1:
						// Enable feature response
						response := make([]byte, 8)
						response[1] = CommandFeatureStateSet
						binary.LittleEndian.PutUint32(response[4:8], uint32(StatusSuccess))
						copy(buffer, response)

						if done != nil {
							*done = uint32(len(response))
						}

						return len(response), nil
					case 2:
						// Response with Invalid State status
						response := make([]byte, 8)
						response[1] = CommandPlatformIDGet
						binary.LittleEndian.PutUint16(response[2:4], 0)                          // ByteCount
						binary.LittleEndian.PutUint32(response[4:8], uint32(StatusInvalidState)) // Status
						copy(buffer, response)

						if done != nil {
							*done = uint32(len(response))
						}

						return len(response), nil
					default:
						// Disable feature response
						response := make([]byte, 8)
						response[1] = CommandFeatureStateSet
						binary.LittleEndian.PutUint32(response[4:8], uint32(StatusSuccess))
						copy(buffer, response)

						if done != nil {
							*done = uint32(len(response))
						}

						return len(response), nil
					}
				}
			},
			wantErr:     true,
			wantErrType: ErrInvalidState,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockHECI := &MockHECI{}
			tt.setupMock(mockHECI)

			client := &Client{
				heci: mockHECI,
			}

			upid, err := client.GetUPID()

			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if tt.wantErrType != nil && err != tt.wantErrType {
					t.Errorf("Expected error %v, got %v", tt.wantErrType, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if tt.checkUPID != nil {
					tt.checkUPID(t, upid)
				}
			}

			// Verify Close was called (except for "not supported" case where close may not be reached)
			if tt.name != "UPID not supported" && !mockHECI.closed {
				t.Error("Expected HECI to be closed")
			}
		})
	}
}
