//go:build windows
// +build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
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

// NewClient creates a new UPID client for Windows
func NewClient() Interface {
	return &Client{
		heci: heci.NewDriver(),
	}
}

// GetUPID retrieves the Intel UPID from the platform via MEI/HECI
// Following Intel UPID SDK workflow: Enable feature → Get UPID → Disable feature
func (c *Client) GetUPID() (*UPID, error) {
	// Parse UPID GUID string
	upidGUID, err := windows.GUIDFromString(UPIDGUID)
	if err != nil {
		log.Tracef("Failed to parse UPID GUID: %v", err)

		return nil, ErrConnectionFailed
	}

	// Initialize HECI driver with UPID GUID
	err = c.heci.InitWithGUID(upidGUID)
	if err != nil {
		log.Tracef("Failed to initialize UPID MEI client: %v", err)

		return nil, ErrUPIDNotSupported
	}
	defer c.close()

	// Step 1: Enable UPID feature (required before reading)
	err = c.setFeatureState(true)
	if err != nil {
		log.Tracef("Failed to enable UPID feature: %v", err)
		// Continue anyway - some platforms may have it already enabled or not require this
	}

	// Step 2: Get the UPID
	upid, getErr := c.getPlatformID()

	// Step 3: Disable UPID feature (security best practice)
	disableErr := c.setFeatureState(false)
	if disableErr != nil {
		log.Tracef("Failed to disable UPID feature: %v", disableErr)
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

	log.Tracef("Setting UPID feature state to %v (value=%d)", enable, featureEnabled)

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

	log.Tracef("UPID feature state set successfully to %v", enable)
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

	log.Tracef("Sending UPID_PLATFORM_ID_GET request: Feature=%d Command=%d ByteCount=%d",
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

	log.Tracef("Sending %d bytes: %x", requestSize, requestBytes)

	bytesWritten, err := c.heci.SendMessage(requestBytes, &requestSize)
	if err != nil {
		log.Tracef("Failed to send UPID command: %v", err)

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
		log.Tracef("Failed to receive UPID response: %v", err)

		return nil, ErrCommandFailed
	}

	if bytesRead == 0 {
		return nil, fmt.Errorf("empty response from UPID MEI client")
	}

	log.Tracef("UPID response: %d bytes received", bytesRead)
	log.Tracef("UPID response data: %x", responseBuffer[:bytesRead])

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

	log.Tracef("UPID header: Feature=%d Command=%d ByteCount=%d Status=%d",
		heciHeader.Feature, heciHeader.Command, heciHeader.ByteCount, status)

	// Verify command matches
	if heciHeader.Command != CommandPlatformIDGet {
		return nil, fmt.Errorf("unexpected command in response: %d (expected %d)", heciHeader.Command, CommandPlatformIDGet)
	}

	// Check response status using official Intel UPID status codes
	if status != uint32(StatusSuccess) {
		log.Tracef("UPID command returned error status: %d", status)

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
		log.Tracef("Short response (%d bytes) with SUCCESS status - UPID not provisioned (expected %d bytes)", bytesRead, expectedFullSize)
		return nil, ErrUPIDNotProvisioned
	}

	// Parse full response with UPID data
	var response PlatformIDGetResponse
	err = binary.Read(bytes.NewBuffer(responseBuffer[:expectedFullSize]), binary.LittleEndian, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse full UPID response: %w", err)
	}

	log.Tracef("PlatformIdType: %d", response.PlatformIdType)

	// Combine OEM and CSME Platform IDs to form the complete 64-byte UPID
	fullUPID := make([]byte, UPIDSize)
	copy(fullUPID[0:32], response.OEMPlatformId[:])
	copy(fullUPID[32:64], response.CSMEPlatformId[:])

	// Create UPID from response with platform ID type
	upid, err := NewUPID(fullUPID, response.PlatformIdType)
	if err != nil {
		return nil, err
	}

	return upid, nil
}

// close releases resources held by the UPID client (internal method)
func (c *Client) close() {
	if c.heci != nil {
		c.heci.Close()
	}
}
