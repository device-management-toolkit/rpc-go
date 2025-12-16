//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// Client represents a Windows UPID client
type Client struct {
	heci heci.Interface
}

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

// NewClient creates a new UPID client for Windows
func NewClient() Interface {
	return &Client{
		heci: heci.NewDriver(),
	}
}

// GetUPID retrieves the Intel UPID from the platform via MEI/HECI
// Following Intel UPID SDK workflow: Enable feature → Get UPID → Disable feature
func (c *Client) GetUPID() (*UPID, error) {
	// Initialize HECI driver with UPID GUID
	driver := c.heci.(*heci.Driver)

	// Parse UPID GUID string - same GUID as Linux MEI_UPID
	upidGUID, err := windows.GUIDFromString("{92136C79-5FEA-4CFD-980E-23BE07FA5E9F}")
	if err != nil {
		log.Debugf("Failed to parse UPID GUID: %v", err)
		return nil, ErrConnectionFailed
	}

	err = driver.InitWithGUID(upidGUID)
	if err != nil {
		log.Debugf("Failed to initialize UPID MEI client: %v", err)

		return nil, ErrConnectionFailed
	}
	defer c.Close()

	// Step 1: Enable UPID feature (required before reading)
	err = c.setFeatureState(true)
	if err != nil {
		log.Debugf("Failed to enable UPID feature: %v", err)
		// Continue anyway - some platforms may have it already enabled or not require this
	}

	// Step 2: Get the UPID
	upid, getErr := c.getPlatformID()

	// Step 3: Disable UPID feature (security best practice)
	disableErr := c.setFeatureState(false)
	if disableErr != nil {
		log.Debugf("Failed to disable UPID feature: %v", disableErr)
		// Non-fatal - log but don't fail the operation
	}

	return upid, getErr
}

// setFeatureState enables or disables the UPID feature
func (c *Client) setFeatureState(enable bool) error {
	var featureEnabled uint8
	if enable {
		featureEnabled = FeatureStateEnabled
	} else {
		featureEnabled = FeatureStateDisabled
	}

	request := PlatformIDFeatureStateSetRequest{
		Header: UPIDHECIHeader{
			Feature:   CommandFeaturePlatformID,
			Command:   CommandFeatureStateSet,
			ByteCount: 1, // 1 byte for FeatureEnabled field
		},
		FeatureEnabled: featureEnabled,
	}

	log.Debugf("Setting UPID feature state to %v (value=%d)", enable, featureEnabled)

	var requestBuffer bytes.Buffer
	err := binary.Write(&requestBuffer, binary.LittleEndian, &request)
	if err != nil {
		return fmt.Errorf("failed to serialize feature state request: %w", err)
	}

	requestBytes := requestBuffer.Bytes()
	requestSize := uint32(len(requestBytes))

	_, err = c.heci.SendMessage(requestBytes, &requestSize)
	if err != nil {
		return fmt.Errorf("failed to send feature state command: %w", err)
	}

	// Read response
	bufferSize := c.heci.GetBufferSize()
	responseBuffer := make([]byte, bufferSize)

	bytesRead, err := c.heci.ReceiveMessage(responseBuffer, &bufferSize)
	if err != nil {
		return fmt.Errorf("failed to receive feature state response: %w", err)
	}

	if bytesRead < 8 {
		return fmt.Errorf("feature state response too short: %d bytes", bytesRead)
	}

	var response PlatformIDFeatureStateSetResponse
	err = binary.Read(bytes.NewBuffer(responseBuffer[:8]), binary.LittleEndian, &response)
	if err != nil {
		return fmt.Errorf("failed to parse feature state response: %w", err)
	}

	if response.Status != uint32(StatusSuccess) {
		return fmt.Errorf("feature state set failed with status: %d", response.Status)
	}

	log.Debugf("UPID feature state set successfully to %v", enable)
	return nil
}

// getPlatformID sends the UPID_PLATFORM_ID_GET command and parses the response
func (c *Client) getPlatformID() (*UPID, error) {
	// Prepare the UPID_PLATFORM_ID_GET request according to Intel UPID SDK
	request := PlatformIDGetRequest{
		Header: UPIDHECIHeader{
			Feature:   CommandFeaturePlatformID, // 0
			Command:   CommandPlatformIDGet,     // 5
			ByteCount: 0,                        // No data after header
		},
	}

	log.Debugf("Sending UPID_PLATFORM_ID_GET request: Feature=%d Command=%d ByteCount=%d",
		request.Header.Feature, request.Header.Command, request.Header.ByteCount)

	// Serialize request
	var requestBuffer bytes.Buffer

	err := binary.Write(&requestBuffer, binary.LittleEndian, &request)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize UPID request: %w", err)
	}

	// Send the command
	requestBytes := requestBuffer.Bytes()
	requestSize := uint32(len(requestBytes))

	log.Debugf("Sending %d bytes: %x", requestSize, requestBytes)

	bytesWritten, err := c.heci.SendMessage(requestBytes, &requestSize)
	if err != nil {
		log.Debugf("Failed to send UPID command: %v", err)

		return nil, ErrCommandFailed
	}

	if bytesWritten != len(requestBytes) {
		return nil, fmt.Errorf("incomplete UPID request sent: %d/%d bytes", bytesWritten, len(requestBytes))
	}

	// Receive the response
	bufferSize := c.heci.GetBufferSize()
	responseBuffer := make([]byte, bufferSize)

	bytesRead, err := c.heci.ReceiveMessage(responseBuffer, &bufferSize)
	if err != nil {
		log.Debugf("Failed to receive UPID response: %v", err)

		return nil, ErrCommandFailed
	}

	if bytesRead == 0 {
		return nil, fmt.Errorf("empty response from UPID MEI client")
	}

	log.Debugf("UPID response: %d bytes received", bytesRead)
	log.Debugf("UPID response data: %x", responseBuffer[:bytesRead])

	// Check minimum response size (header is 4 bytes + status is 4 bytes = 8 bytes minimum)
	const minResponseSize = 8
	if bytesRead < minResponseSize {
		return nil, fmt.Errorf("UPID response too short: %d bytes (expected at least %d)", bytesRead, minResponseSize)
	}

	// Parse header and status (8 bytes minimum)
	var heciHeader UPIDHECIHeader
	err = binary.Read(bytes.NewBuffer(responseBuffer[:4]), binary.LittleEndian, &heciHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse UPID response header: %w", err)
	}

	var status uint32
	err = binary.Read(bytes.NewBuffer(responseBuffer[4:8]), binary.LittleEndian, &status)
	if err != nil {
		return nil, fmt.Errorf("failed to parse UPID response status: %w", err)
	}

	log.Debugf("UPID header: Feature=%d Command=%d ByteCount=%d Status=%d",
		heciHeader.Feature, heciHeader.Command, heciHeader.ByteCount, status)

	// Verify command matches
	if heciHeader.Command != CommandPlatformIDGet {
		return nil, fmt.Errorf("unexpected command in response: %d (expected %d)", heciHeader.Command, CommandPlatformIDGet)
	}

	// Check response status using official Intel UPID status codes
	if status != uint32(StatusSuccess) {
		log.Debugf("UPID command returned error status: %d", status)

		switch uint8(status) {
		case StatusFeatureNotSupported:
			return nil, ErrFeatureNotSupported
		case StatusInvalidInputParameter:
			return nil, ErrInvalidInputParameter
		case StatusInternalError:
			return nil, ErrInternalError
		case StatusNotAllowedAfterEOP:
			return nil, ErrNotAllowedAfterEOP
		case StatusNotAllowedAfterManufLock:
			return nil, ErrNotAllowedAfterManufLock
		case StatusMaxCountersExceeded:
			return nil, ErrMaxCountersExceeded
		case StatusInvalidState:
			// For GetPlatformID: called after EOP and EOM with UPID disabled
			return nil, ErrInvalidState
		case StatusNotAllowedAfterCBD:
			return nil, ErrNotAllowedAfterCBD
		default:
			return nil, fmt.Errorf("UPID command failed with status: 0x%08x", status)
		}
	}

	// Status is SUCCESS - check if we have the full UPID data
	// Expected: Header(4) + Status(4) + PlatformIdType(4) + OEMPlatformId(32) + CSMEPlatformId(32) = 76 bytes
	const expectedFullSize = 76
	if bytesRead < expectedFullSize {
		// Short response with SUCCESS status indicates UPID not provisioned
		log.Debugf("Short response (%d bytes) with SUCCESS status - UPID not provisioned (expected %d bytes)", bytesRead, expectedFullSize)
		return nil, ErrUPIDNotProvisioned
	}

	// Parse full response with UPID data
	var response PlatformIDGetResponse
	err = binary.Read(bytes.NewBuffer(responseBuffer[:expectedFullSize]), binary.LittleEndian, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse full UPID response: %w", err)
	}

	log.Debugf("PlatformIdType: %d", response.PlatformIdType)

	// Combine OEM and CSME Platform IDs to form the complete 64-byte UPID
	fullUPID := make([]byte, UPIDSize)
	copy(fullUPID[0:32], response.OEMPlatformId[:])
	copy(fullUPID[32:64], response.CSMEPlatformId[:])

	// Create UPID from response
	upid, err := NewUPID(fullUPID)
	if err != nil {
		return nil, err
	}

	return upid, nil
}

// IsSupported checks if UPID is supported on this platform
func (c *Client) IsSupported() bool {
	driver := c.heci.(*heci.Driver)

	// Parse UPID GUID string - same GUID as Linux MEI_UPID
	upidGUID, err := windows.GUIDFromString("{92136C79-5FEA-4CFD-980E-23BE07FA5E9F}")
	if err != nil {
		log.Debugf("Failed to parse UPID GUID: %v", err)
		return false
	}

	err = driver.InitWithGUID(upidGUID)
	if err != nil {
		log.Debugf("UPID MEI client initialization failed: %v", err)
		return false
	}
	defer c.Close()

	return true
}

// Close releases resources held by the UPID client
func (c *Client) Close() error {
	if c.heci != nil {
		driver := c.heci.(*heci.Driver)
		driver.Close()
	}
	return nil
}
