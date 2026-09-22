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
)

// Command wraps a HECI interface for UPID operations.
// Follows the same pattern as pthi.Command and hotham.Command.
type Command struct {
	Heci heci.Interface
}

// GetUPID retrieves the Intel UPID from the platform via MEI/HECI.
// Following Intel UPID SDK workflow: Enable feature -> Get UPID -> Disable feature.
// It initializes and cleans up the HECI connection automatically.
func (c *Command) GetUPID() (*UPID, error) {
	if err := c.initGUID(); err != nil {
		return nil, err
	}
	defer c.Close()

	// Step 1: Enable UPID feature (required before reading)
	err := c.setFeatureState(true)
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

// Close releases resources held by the UPID command.
func (c *Command) Close() {
	if c.Heci != nil {
		c.Heci.Close()
	}
}

// setFeatureState enables or disables the UPID feature
func (c *Command) setFeatureState(enable bool) error {
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

	response, err := c.call(&request)
	if err != nil {
		return fmt.Errorf("feature state set: %w", err)
	}

	status, err := parseResponseHeader(response, CommandFeaturePlatformID, CommandFeatureStateSet)
	if err != nil {
		return fmt.Errorf("feature state set: %w", err)
	}

	if status != uint32(StatusSuccess) {
		return fmt.Errorf("feature state set: %w", mapStatusError(status))
	}

	log.Tracef("UPID feature state set successfully to %v", enable)

	return nil
}

// getPlatformID sends the UPID_PLATFORM_ID_GET command and parses the response
func (c *Command) getPlatformID() (*UPID, error) {
	request := PlatformIDGetRequest{
		Header: UPIDHECIHeader{
			Feature:   CommandFeaturePlatformID,
			Command:   CommandPlatformIDGet,
			ByteCount: 0, // No data after header
		},
	}

	response, err := c.call(&request)
	if err != nil {
		return nil, err
	}

	return parseGetPlatformIDResponse(response)
}

// call serializes request, sends it to the UPID MEI client and returns the
// raw response. Parsing the response is left to the caller.
func (c *Command) call(request any) ([]byte, error) {
	var requestBuffer bytes.Buffer

	err := binary.Write(&requestBuffer, binary.LittleEndian, request)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize UPID request: %w", err)
	}

	requestBytes := requestBuffer.Bytes()
	requestSize := uint32(len(requestBytes))

	log.Tracef("Sending %d bytes: %x", requestSize, requestBytes)

	bytesWritten, err := c.Heci.SendMessage(requestBytes, &requestSize)
	if err != nil {
		return nil, fmt.Errorf("%w: send: %w", ErrCommandFailed, err)
	}

	if bytesWritten != len(requestBytes) {
		return nil, fmt.Errorf("%w: incomplete request sent: %d/%d bytes", ErrCommandFailed, bytesWritten, len(requestBytes))
	}

	bufferSize := c.Heci.GetBufferSize()
	responseBuffer := make([]byte, bufferSize)

	bytesRead, err := c.Heci.ReceiveMessage(responseBuffer, &bufferSize)
	if err != nil {
		return nil, fmt.Errorf("%w: receive: %w", ErrCommandFailed, err)
	}

	if bytesRead == 0 {
		return nil, fmt.Errorf("%w: empty response", ErrInvalidResponse)
	}

	log.Tracef("UPID response: %d bytes: %x", bytesRead, responseBuffer[:bytesRead])

	return responseBuffer[:bytesRead], nil
}

// parseResponseHeader decodes the header and UINT32 status that start every
// UPID response and verifies the response belongs to the expected feature
// and command.
func parseResponseHeader(response []byte, feature, command uint8) (uint32, error) {
	if len(response) < minResponseSize {
		return 0, fmt.Errorf("%w: response too short: %d bytes (expected at least %d)", ErrInvalidResponse, len(response), minResponseSize)
	}

	var header UPIDHECIHeader

	err := binary.Read(bytes.NewReader(response[:headerSize]), binary.LittleEndian, &header)
	if err != nil {
		return 0, fmt.Errorf("failed to parse UPID response header: %w", err)
	}

	status := binary.LittleEndian.Uint32(response[headerSize:minResponseSize])

	log.Tracef("UPID header: Feature=%d Command=%d ByteCount=%d Status=%d",
		header.Feature, header.Command, header.ByteCount, status)

	if header.Feature != feature || header.Command != command {
		return 0, fmt.Errorf("%w: unexpected feature/command in response: %d/%d (expected %d/%d)", ErrInvalidResponse, header.Feature, header.Command, feature, command)
	}

	return status, nil
}

// parseGetPlatformIDResponse decodes the raw HECI response for a PlatformIDGet command.
func parseGetPlatformIDResponse(responseBuffer []byte) (*UPID, error) {
	bytesRead := len(responseBuffer)

	status, err := parseResponseHeader(responseBuffer, CommandFeaturePlatformID, CommandPlatformIDGet)
	if err != nil {
		return nil, err
	}

	// Check response status using official Intel UPID status codes
	if status != uint32(StatusSuccess) {
		return nil, mapStatusError(status)
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

	return NewUPID(fullUPID, response.PlatformIdType)
}

// mapStatusError converts an Intel UPID status code to a Go error.
func mapStatusError(status uint32) error {
	log.Tracef("UPID command returned error status: %d", status)

	switch uint8(status) {
	case StatusFeatureNotSupported:
		return ErrFeatureNotSupported
	case StatusInvalidInputParameter:
		return ErrInvalidInputParameter
	case StatusInternalError:
		return ErrInternalError
	case StatusNotAllowedAfterEOP:
		return ErrNotAllowedAfterEOP
	case StatusNotAllowedAfterManufLock:
		return ErrNotAllowedAfterManufLock
	case StatusMaxCountersExceeded:
		return ErrMaxCountersExceeded
	case StatusInvalidState:
		return ErrInvalidState
	case StatusNotAllowedAfterCBD:
		return ErrNotAllowedAfterCBD
	default:
		return fmt.Errorf("UPID command failed with status: 0x%08x", status)
	}
}
