/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import "errors"

// UPID constants
const (
	// UPIDSize is the total size of the UPID in bytes
	UPIDSize = 64
	// OEMPlatformIDSize is the size of the OEM Platform ID (first 32 bytes)
	OEMPlatformIDSize = 32
	// HWSerialNumSize is the size of the Hardware Serial Number (second 32 bytes)
	HWSerialNumSize = 32
)

// UPID Command Feature Codes (from Intel UPID Attestation SDK)
const (
	CommandFeaturePlatformID uint8 = 0 // UPID_COMMAND_FEATURE_PLATFORM_ID
)

// UPID Command Codes (from Intel UPID Attestation SDK)
const (
	CommandFeatureSupportGet        uint8 = 0 // UPID_PLATFORM_ID_FEATURE_SUPPORT_GET_CMD
	CommandFeatureStateGet          uint8 = 1 // UPID_PLATFORM_ID_FEATURE_STATE_GET_CMD
	CommandFeatureStateSet          uint8 = 2 // UPID_PLATFORM_ID_FEATURE_STATE_SET_CMD
	CommandFeatureStateOSControlGet uint8 = 3 // UPID_PLATFORM_ID_FEATURE_STATE_OS_CONTROL_GET_CMD
	CommandFeatureStateOSControlSet uint8 = 4 // UPID_PLATFORM_ID_FEATURE_STATE_OS_CONTROL_SET_CMD
	CommandPlatformIDGet            uint8 = 5 // UPID_PLATFORM_ID_GET_CMD
	CommandRefurbishCounterGet      uint8 = 6 // UPID_PLATFORM_ID_REFURBISH_COUNTER_GET_CMD
	CommandOEMPlatformIDUpdate      uint8 = 7 // UPID_OEM_PLATFORM_ID_UPDATE_CMD
)

// UPID OEM Platform ID Types (from Intel UPID Attestation SDK)
const (
	PlatformIDTypeNotSet          uint32 = 0 // UPID_OEM_PLATFORM_ID_TYPE_NOT_SET
	PlatformIDTypeBinary          uint32 = 1 // UPID_OEM_PLATFORM_ID_TYPE_BINARY
	PlatformIDTypePrintableString uint32 = 2 // UPID_OEM_PLATFORM_ID_TYPE_PRINTABLE_STRING
)

// UPID Feature States
const (
	FeatureStateDisabled uint8 = 0x00
	FeatureStateEnabled  uint8 = 0x01
)

// Intel UPID Status Codes (from Intel UPID Attestation SDK Documentation)
const (
	StatusSuccess                  uint8 = 0
	StatusFeatureNotSupported      uint8 = 1
	StatusInvalidInputParameter    uint8 = 2
	StatusInternalError            uint8 = 3
	StatusNotAllowedAfterEOP       uint8 = 4
	StatusNotAllowedAfterManufLock uint8 = 5
	StatusMaxCountersExceeded      uint8 = 6
	StatusInvalidState             uint8 = 7
	StatusReserved2                uint8 = 8
	StatusNotAllowedAfterCBD       uint8 = 9
)

// Common errors
var (
	ErrUPIDNotSupported         = errors.New("intel UPID is not supported on this platform")
	ErrUPIDNotEnabled           = errors.New("intel UPID feature is not enabled")
	ErrUPIDNotProvisioned       = errors.New("intel UPID is not provisioned on this platform")
	ErrInvalidResponse          = errors.New("invalid response from UPID MEI client")
	ErrConnectionFailed         = errors.New("failed to connect to UPID MEI client")
	ErrCommandFailed            = errors.New("UPID command failed")
	ErrInsufficientPriv         = errors.New("insufficient privileges to access UPID")
	ErrFeatureNotSupported      = errors.New("UPID feature not supported")
	ErrInvalidInputParameter    = errors.New("invalid input parameter")
	ErrInternalError            = errors.New("UPID internal error")
	ErrNotAllowedAfterEOP       = errors.New("operation not allowed after end of post")
	ErrInvalidState             = errors.New("UPID is in invalid state or disabled after EOP/EOM")
	ErrNotAllowedAfterManufLock = errors.New("operation not allowed after manufacturing lock")
	ErrMaxCountersExceeded      = errors.New("maximum counters exceeded")
	ErrNotAllowedAfterCBD       = errors.New("operation not allowed after core BIOS done")
)

// UPID represents the Intel Unique Platform Identifier
type UPID struct {
	// Full 64-byte UPID
	Raw []byte `json:"raw"`
	// OEMPlatformID is the first 32 bytes
	OEMPlatformID []byte `json:"oemPlatformID"`
	// HWSerialNum is the second 32 bytes
	HWSerialNum []byte `json:"hwSerialNum"`
}

// Interface defines the operations for Intel UPID
type Interface interface {
	// GetUPID retrieves the Intel UPID from the platform
	// Returns the UPID struct or an error if not supported/enabled
	GetUPID() (*UPID, error)

	// IsSupported checks if Intel UPID is supported on this platform
	IsSupported() bool

	// Close releases any resources held by the UPID client
	Close() error
}

// NewUPID creates a new UPID structure from raw 64-byte data
func NewUPID(raw []byte) (*UPID, error) {
	if len(raw) != UPIDSize {
		return nil, errors.New("invalid UPID size")
	}

	return &UPID{
		Raw:           raw,
		OEMPlatformID: raw[:OEMPlatformIDSize],
		HWSerialNum:   raw[OEMPlatformIDSize:],
	}, nil
}

// String returns a hex-encoded string representation of the full UPID
func (u *UPID) String() string {
	if u == nil || u.Raw == nil {
		return ""
	}

	result := ""
	for i, b := range u.Raw {
		result += hexChar(b>>4) + hexChar(b&0x0F)
		if i == 31 {
			result += "\n          "
		}
	}

	return result
}

func hexChar(n byte) string {
	if n < 10 {
		return string(rune('0' + n))
	}

	return string(rune('A' + n - 10))
}
