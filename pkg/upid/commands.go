/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	log "github.com/sirupsen/logrus"
)

// DefaultCommandTimeout bounds each UPID HECI round-trip. The 2.x MEI drivers
// block without a deadline on receive, so firmware that accepts a request but
// never answers would otherwise hang the caller (and with it `rpc activate`).
const DefaultCommandTimeout = 10 * time.Second

// Command wraps a HECI interface for UPID operations.
// Follows the same pattern as pthi.Command.
type Command struct {
	Heci heci.GUIDInterface
	// Timeout bounds each HECI round-trip; zero means DefaultCommandTimeout.
	Timeout time.Duration

	timedOut bool
	closed   bool
	// newHECI supplies a separate connection for restoration after a timeout.
	newHECI func() heci.GUIDInterface
}

// NewCommand creates a new UPID command backed by the platform HECI driver.
func NewCommand() Interface {
	return &Command{
		Heci: heci.NewDriver(),
	}
}

// GetUPID retrieves the Intel UPID from the platform via MEI/HECI.
// Following Intel UPID SDK workflow: Enable feature -> Get UPID -> Disable feature.
// It initializes and cleans up the HECI connection automatically.
func (c *Command) GetUPID() (*UPID, error) {
	var upid *UPID

	err := c.withFeatureEnabled(func() error {
		var err error

		upid, err = c.getPlatformID()

		return err
	})

	return upid, err
}

// withFeatureEnabled opens the MEI client, makes sure the UPID platform ID
// feature is enabled while fn runs, and leaves it the way it was found.
// Platform ID commands such as GET fail with UPID_STATUS_INVALID_STATE while
// the feature is disabled. FEATURE_STATE_SET is the OS-side runtime toggle
// (honored once BIOS has granted OS control); the current state is read first
// so a feature the platform already had enabled is never switched off.
func (c *Command) withFeatureEnabled(fn func() error) error {
	if err := c.initGUID(); err != nil {
		return err
	}
	defer c.Close()

	enabled, err := c.getFeatureState()
	if err != nil {
		log.Tracef("Unable to read UPID feature state; reading without changing it: %v", err)

		return fn()
	}

	if !enabled {
		// Enable UPID feature (required before reading)
		if err := c.setFeatureState(true); err != nil {
			log.Tracef("Failed to enable UPID feature: %v", err)
			// Continue anyway - the platform ID read reports the real state
		} else {
			// Disable it again afterwards (security best practice); non-fatal
			defer func() {
				if err := c.restoreFeatureState(); err != nil {
					log.Debugf("Failed to disable UPID feature: %v", err)
				}
			}()
		}
	}

	return fn()
}

// Close releases resources held by the UPID command.
func (c *Command) Close() {
	if c.Heci != nil && !c.closed {
		c.Heci.Close()
		c.closed = true
	}
}

// restoreFeatureState disables a feature this request observed disabled and enabled.
// A timed-out connection cannot be reused: its outstanding receive could consume
// a later response. Close it and restore through a fresh, independently bounded
// connection, without clearing the original command's timeout guard.
func (c *Command) restoreFeatureState() error {
	if !c.timedOut {
		return c.setFeatureState(false)
	}

	c.Close()

	driver := heci.GUIDInterface(heci.NewDriver())
	if c.newHECI != nil {
		driver = c.newHECI()
	}

	recovery := &Command{Heci: driver, Timeout: c.timeout()}
	if err := recovery.initGUID(); err != nil {
		return err
	}
	defer recovery.Close()

	return recovery.setFeatureState(false)
}

// initGUID connects the HECI driver to the UPID MEI client.
func (c *Command) initGUID() error {
	if err := c.Heci.InitWithGUID(UPIDGUID); err != nil {
		log.Tracef("Failed to initialize UPID MEI client: %v", err)

		return ErrUPIDNotSupported
	}

	c.closed = false

	return nil
}

func (c *Command) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}

	return DefaultCommandTimeout
}

// getFeatureState reports whether the UPID platform ID feature is enabled.
func (c *Command) getFeatureState() (bool, error) {
	request := PlatformIDFeatureStateGetRequest{
		Header: UPIDHECIHeader{
			Feature:   CommandFeaturePlatformID,
			Command:   CommandFeatureStateGet,
			ByteCount: 0,
		},
	}

	response, err := c.call(&request)
	if err != nil {
		return false, fmt.Errorf("feature state get: %w", err)
	}

	status, err := parseResponseHeader(response, CommandFeaturePlatformID, CommandFeatureStateGet)
	if err != nil {
		return false, fmt.Errorf("feature state get: %w", err)
	}

	if status != StatusSuccess {
		return false, fmt.Errorf("feature state get: %w", mapStatusError(status))
	}

	if len(response) < featureStateResponseSize {
		return false, fmt.Errorf("feature state get: %w: state missing from response", ErrInvalidResponse)
	}

	enabled := response[minResponseSize] == FeatureStateEnabled

	log.Tracef("UPID feature state: enabled=%v", enabled)

	return enabled, nil
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

	if status != StatusSuccess {
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
// raw response. Parsing the response is left to the caller. Each round-trip
// is bounded by Timeout; once a command has timed out the client is assumed
// hung and every later command fails fast with ErrCommandTimeout.
func (c *Command) call(request any) ([]byte, error) {
	if c.timedOut {
		return nil, ErrCommandTimeout
	}

	var requestBuffer bytes.Buffer

	err := binary.Write(&requestBuffer, binary.LittleEndian, request)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize UPID request: %w", err)
	}

	type result struct {
		data []byte
		err  error
	}

	done := make(chan result, 1)

	// The driver call runs in its own goroutine so the caller can give up on a
	// client that never answers. On timeout the goroutine stays blocked until
	// Close cancels the I/O (Windows) or the process exits (Linux); it owns its
	// buffer, so nothing it writes later is observed here.
	go func() {
		data, err := c.roundTrip(requestBuffer.Bytes())
		done <- result{data: data, err: err}
	}()

	timer := time.NewTimer(c.timeout())
	defer timer.Stop()

	select {
	case res := <-done:
		return res.data, res.err
	case <-timer.C:
		c.timedOut = true

		log.Debugf("UPID command timed out after %v", c.timeout())

		return nil, ErrCommandTimeout
	}
}

// roundTrip writes requestBytes to the MEI client and returns the raw response.
func (c *Command) roundTrip(requestBytes []byte) ([]byte, error) {
	requestSize := uint32(len(requestBytes))

	log.Tracef("Sending %d bytes: %x", requestSize, requestBytes)

	bytesWritten, err := c.Heci.SendMessage(requestBytes, &requestSize)
	if err != nil {
		return nil, fmt.Errorf("%w: send: %w", ErrCommandFailed, err)
	}

	if int(bytesWritten) != len(requestBytes) {
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
	if status != StatusSuccess {
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

// mapStatusError converts an Intel UPID status code to a Go error. UPID_STATUS
// is a 32-bit enum, so the full value is compared: truncating it would fold
// e.g. 0x101 onto "feature not supported".
func mapStatusError(status uint32) error {
	log.Tracef("UPID command returned error status: %d", status)

	switch status {
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
		return fmt.Errorf("%w: status 0x%08x", ErrCommandFailed, status)
	}
}
