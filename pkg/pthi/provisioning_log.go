/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package pthi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	GET_HBP_PROV_LOG_REQUEST  = 0x400008f // AMT_HOSTIF_CFG_GET_HBP_PROV_LOG
	GET_HBP_PROV_LOG_RESPONSE = 0x480008f
)

// ProvisioningAttemptResult is AMT_HOSTIF_PROV_ATTEMPT_RESULT, the outcome of
// the latest host-based provisioning attempt.
type ProvisioningAttemptResult uint32

const (
	PROV_RES_INVALID                 ProvisioningAttemptResult = 0
	PROV_RES_SUCCESS                 ProvisioningAttemptResult = 1
	PROV_RES_GEN_ERR                 ProvisioningAttemptResult = 2
	PROV_RES_INVALID_STATE           ProvisioningAttemptResult = 3
	PROV_RES_AUTH_FAIL               ProvisioningAttemptResult = 4
	PROV_RES_INVALID_CERT            ProvisioningAttemptResult = 5
	PROV_RES_UNTRUSTED_ROOT          ProvisioningAttemptResult = 6
	PROV_RES_TEP_HASH_MISMATCH       ProvisioningAttemptResult = 7
	PROV_RES_TEP_INVALID_CERT_TIME   ProvisioningAttemptResult = 8
	PROV_RES_TEP_OWNERSHIP_EXPIRED   ProvisioningAttemptResult = 9
	PROV_RES_TEP_OWNERSHIP_SUSPENDED ProvisioningAttemptResult = 10
	PROV_RES_TEP_MISSING_CA_OID      ProvisioningAttemptResult = 11
)

var provisioningAttemptResultNames = map[ProvisioningAttemptResult]string{
	PROV_RES_INVALID:                 "No provisioning attempt recorded",
	PROV_RES_SUCCESS:                 "Success",
	PROV_RES_GEN_ERR:                 "General error",
	PROV_RES_INVALID_STATE:           "Invalid state",
	PROV_RES_AUTH_FAIL:               "Authentication failed",
	PROV_RES_INVALID_CERT:            "Invalid certificate",
	PROV_RES_UNTRUSTED_ROOT:          "Untrusted root certificate",
	PROV_RES_TEP_HASH_MISMATCH:       "TEP owner credential hash mismatch",
	PROV_RES_TEP_INVALID_CERT_TIME:   "Invalid TEP certificate time",
	PROV_RES_TEP_OWNERSHIP_EXPIRED:   "Expired TEP ownership",
	PROV_RES_TEP_OWNERSHIP_SUSPENDED: "Suspended TEP ownership",
	PROV_RES_TEP_MISSING_CA_OID:      "Missing TEP CA OID in the certificate policies extension",
}

func (r ProvisioningAttemptResult) String() string {
	if name, ok := provisioningAttemptResultNames[r]; ok {
		return name
	}

	return fmt.Sprintf("Unknown provisioning result (%d)", uint32(r))
}

// IsTEP reports whether the result is a Trusted Endpoint Provisioning failure.
func (r ProvisioningAttemptResult) IsTEP() bool {
	return r >= PROV_RES_TEP_HASH_MISMATCH && r <= PROV_RES_TEP_MISSING_CA_OID
}

type GetProvisioningLogRequest struct {
	Header  MessageHeader
	Version uint8
}

// ProvisioningLog is HBP_PROV_LOG: the latest host-based provisioning attempt.
// It is volatile (lost on CSME reset). Times are UTC Unix seconds.
type ProvisioningLog struct {
	CcmProvisioningStatus ProvisioningAttemptResult
	CcmProvisioningTime   uint32
	AcmProvisioningStatus ProvisioningAttemptResult
	AcmStartingTime       uint32
	AcmCompletionTime     uint32
}

type GetProvisioningLogResponse struct {
	Header          ResponseMessageHeader
	Version         uint8
	ProvisioningLog ProvisioningLog
}

// ErrProvisioningLogTruncated is returned when the firmware response is shorter than a full log.
var ErrProvisioningLogTruncated = errors.New("provisioning log response truncated")

// getProvisioningLogRequestSize is the 12-byte header plus the 1-byte version.
const getProvisioningLogRequestSize = GET_REQUEST_SIZE + 1

// GetProvisioningLog sends AMT_HOSTIF_CFG_GET_HBP_PROV_LOG, which reports the
// latest CCM/ACM host-based provisioning result, including TEP-specific
// failure reasons.
func (pthi Command) GetProvisioningLog() (response GetProvisioningLogResponse, err error) {
	command := GetProvisioningLogRequest{
		Header:  CreateRequestHeader(GET_HBP_PROV_LOG_REQUEST, 1),
		Version: 0,
	}

	var binBuf bytes.Buffer

	if err := binary.Write(&binBuf, binary.LittleEndian, command); err != nil {
		return response, err
	}

	result, err := pthi.Call(binBuf.Bytes(), getProvisioningLogRequestSize)
	if err != nil {
		return response, err
	}

	buf := bytes.NewBuffer(result)
	response.Header = ReadHeaderResponse(buf)

	if response.Header.Status != AMT_STATUS_SUCCESS {
		return response, fmt.Errorf("get provisioning log failed: %s (0x%x)", response.Header.Status, uint32(response.Header.Status))
	}

	// Header.Length counts the payload after the 12-byte header: status, version and log.
	const payloadSize = 4 + 1 + 20
	if response.Header.Header.Length < payloadSize {
		return response, fmt.Errorf("%w: %d bytes, want %d", ErrProvisioningLogTruncated, response.Header.Header.Length, payloadSize)
	}

	if err := binary.Read(buf, binary.LittleEndian, &response.Version); err != nil {
		return response, err
	}

	if err := binary.Read(buf, binary.LittleEndian, &response.ProvisioningLog); err != nil {
		return response, err
	}

	return response, nil
}
