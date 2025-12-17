//go:build linux
// +build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}

	// Ensure it implements the Interface
	_ = client
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
			upid, err := NewUPID(tt.input)
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
				Raw: make([]byte, UPIDSize),
			},
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name: "Valid UPID with OEM provisioned (shows both OEM and CSME)",
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
			},
			expected: "AB00000000000000000000000000000000000000000000000000000000000000\n          CDEF000000000000000000000000000000000000000000000000000000000000",
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

	upid, err := NewUPID(upidData)
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
	// Set first byte to 0x12, second to 0x34 for verification
	upidData[0] = 0x12
	upidData[1] = 0x34
	upidData[32] = 0xAB
	upidData[33] = 0xCD

	upid, err := NewUPID(upidData)
	if err != nil {
		t.Fatalf("NewUPID() failed: %v", err)
	}

	str := upid.String()

	// Verify the string starts with our test values (uppercase hex)
	if len(str) < 4 {
		t.Fatal("UPID string too short")
	}

	// First 4 hex chars should be "1234"
	if str[0:4] != "1234" {
		t.Errorf("UPID string doesn't start with expected hex: got %s, want 1234...", str[0:4])
	}

	// Verify it contains newline and spaces for second line formatting
	if !contains(str, "\n") {
		t.Error("UPID string missing newline separator")
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
