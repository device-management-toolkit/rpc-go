/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"errors"
)

// UPID constants
const (
	// UPIDSize is the total size of the UPID in bytes
	UPIDSize = 64
	// OEMPlatformIDSize is the size of the OEM Platform ID (first 32 bytes)
	OEMPlatformIDSize = 32
	// HWSerialNumSize is the size of the Hardware Serial Number (second 32 bytes)
	HWSerialNumSize = 32
	// UPIDGUID is the Intel ME UPID interface GUID
	UPIDGUID = "{92136C79-5FEA-4CFD-980E-23BE07FA5E9F}"
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

// UPIDHECIHeader represents the Intel UPID HECI message header
type UPIDHECIHeader struct {
	Feature   uint8  // Command feature code (UPID_COMMAND_FEATURE_PLATFORM_ID = 0)
	Command   uint8  // Command code (UPID_PLATFORM_ID_GET_CMD = 5)
	ByteCount uint16 // Total length excluding header
}

// PlatformIDFeatureStateSetRequest represents a UPID_PLATFORM_ID_FEATURE_STATE_SET request
type PlatformIDFeatureStateSetRequest struct {
	Header         UPIDHECIHeader
	FeatureEnabled uint8 // Feature state (0=disabled, 1=enabled)
}

// PlatformIDFeatureStateSetResponse represents the response for UPID_PLATFORM_ID_FEATURE_STATE_SET command
type PlatformIDFeatureStateSetResponse struct {
	Header UPIDHECIHeader
	Status uint32 // UPID_STATUS (4 bytes enum)
}

// PlatformIDGetRequest represents a UPID_PLATFORM_ID_GET request
type PlatformIDGetRequest struct {
	Header UPIDHECIHeader
}

// PlatformIDGetResponse represents the response for UPID_PLATFORM_ID_GET command
type PlatformIDGetResponse struct {
	Header         UPIDHECIHeader
	Status         uint32                  // UPID_STATUS (4 bytes enum)
	PlatformIdType uint32                  // UPID_OEM_PLATFORM_ID_TYPE (4 bytes enum)
	OEMPlatformId  [OEMPlatformIDSize]byte // 32 bytes
	CSMEPlatformId [HWSerialNumSize]byte   // 32 bytes
}

// UPID represents the Intel Unique Platform Identifier
type UPID struct {
	// Full 64-byte UPID
	Raw []byte `json:"-"`
	// OEMPlatformID is the first 32 bytes
	OEMPlatformID []byte `json:"-"`
	// HWSerialNum is the second 32 bytes
	HWSerialNum []byte `json:"-"`
	// PlatformIdType indicates the type of OEM Platform ID (0=Not Set, 1=Binary, 2=Printable String)
	PlatformIdType uint32 `json:"platformIdType"`
}

// Interface defines the operations for Intel UPID
type Interface interface {
	// GetUPID retrieves the Intel UPID from the platform
	// Returns the UPID struct or an error if not supported/enabled
	// Automatically checks support and manages resource cleanup
	GetUPID() (*UPID, error)
}

// NewUPID creates a new UPID structure from raw 64-byte data and platform ID type
func NewUPID(raw []byte, platformIdType uint32) (*UPID, error) {
	if len(raw) != UPIDSize {
		return nil, errors.New("invalid UPID size")
	}

	return &UPID{
		Raw:            raw,
		OEMPlatformID:  raw[:OEMPlatformIDSize],
		HWSerialNum:    raw[OEMPlatformIDSize:],
		PlatformIdType: platformIdType,
	}, nil
}
