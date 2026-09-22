/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// TEPNonce is a 20-byte request ID or CSME nonce.
type TEPNonce [TEPNonceSize]byte

// TEPInterface defines the Intel TEP operations exposed by the UPID MEI client.
type TEPInterface interface {
	// TEPGetCapabilities returns the features that can be provisioned via TEP.
	TEPGetCapabilities() (*TEPCapabilities, error)
	// TEPGetVouchers returns the IDs of the ownership vouchers stored in CSME.
	TEPGetVouchers() ([]TEPVoucherID, error)
	// TEPGetAllVoucherIDs returns the IDs of all ownership vouchers stored in CSME.
	TEPGetAllVoucherIDs() ([]TEPVoucherID, error)
	// TEPGetVoucherStateByFeature returns the ownership context for a feature (unsigned).
	TEPGetVoucherStateByFeature(feature TEPFeature) (*TEPVoucherState, error)
	// TEPGetOwnershipState returns the CSME-signed ownership context for a voucher.
	TEPGetOwnershipState(reqID TEPNonce, voucherID TEPVoucherID) (*TEPOwnershipState, error)
	// TEPGetTimeSyncNonce returns a CSME-signed nonce to include in OCSP requests.
	TEPGetTimeSyncNonce(reqID TEPNonce) (*TEPTimeSyncNonce, error)
}

var _ TEPInterface = (*Command)(nil)

// ErrTEPRequestIDMismatch is returned when CSME echoes a different req_id than was sent.
var ErrTEPRequestIDMismatch = errors.New("TEP response request ID does not match request")

// TEPCapabilities is the parsed TEP_GET_CAPABILITIES_CMD response.
type TEPCapabilities struct {
	// MaxVouchers is the number of ownership vouchers CSME can hold.
	MaxVouchers int
	Features    []TEPFeature
}

// Supports reports whether feature can be provisioned via TEP.
func (c *TEPCapabilities) Supports(feature TEPFeature) bool {
	for _, f := range c.Features {
		if f == feature {
			return true
		}
	}

	return false
}

// TEPVoucherState is the parsed TEP_GET_VOUCHER_STATE_BY_FEATURE_CMD response.
type TEPVoucherState struct {
	VoucherVersion uint32
	Context        TEPOwnershipContext
}

// TEPOwnershipState is the parsed TEP_GET_OWNERSHIP_STATE_CMD response.
type TEPOwnershipState struct {
	Context   TEPOwnershipContext
	Signature CSMESignature
	// SignedData is Status || Req_id || OwnershipState || SignatureMechanism || Timestamp
	// as received, for verifying Signature.
	SignedData []byte
}

// TEPTimeSyncNonce is the parsed TEP_GET_TIME_SYNC_NONCE_CMD response.
type TEPTimeSyncNonce struct {
	// CSMENonce is valid for 10 minutes; CSME returns the same nonce while it is valid.
	CSMENonce TEPNonce
	Signature CSMESignature
	// SignedData is Status || Req_id || CSME_nonce || SignatureMechanism || Timestamp
	// as received, for verifying Signature.
	SignedData []byte
}

// Request payloads. Each embeds the UPID header; ByteCount is the payload size.
type (
	tepEmptyRequest struct {
		Header UPIDHECIHeader
	}
	tepFeatureRequest struct {
		Header  UPIDHECIHeader
		Feature TEPOID
	}
	tepReqIDRequest struct {
		Header UPIDHECIHeader
		ReqID  TEPNonce
	}
	tepOwnershipStateRequest struct {
		Header    UPIDHECIHeader
		ReqID     TEPNonce
		VoucherID TEPVoucherID
	}
)

const (
	// csmeSignatureFixedSize is CSME_SIGNATURE up to (not including) the certificate buffer
	csmeSignatureFixedSize = 4 + 4 + CSMESignatureSize + 2*CSMESignatureMaxCerts
	// tepOwnershipContextSize is the size of TEP_OWNERSHIP_CONTEXT (firmware sends structs packed)
	tepOwnershipContextSize = 1138
	// uint32Size is the size of a UINT32 field
	uint32Size = 4
)

// tepHeader builds the header for a TEP request whose full encoded size
// (header included) is binary.Size(request).
func tepHeader(command uint8, request any) UPIDHECIHeader {
	return UPIDHECIHeader{
		Feature:   CommandFeatureTEP,
		Command:   command,
		ByteCount: uint16(binary.Size(request) - headerSize),
	}
}

// tepCall opens the UPID MEI client, sends request and returns the response
// payload (the bytes after header and status) once the header and TEP status
// have been checked.
func (c *Command) tepCall(command uint8, request any) ([]byte, error) {
	if err := c.initGUID(); err != nil {
		return nil, err
	}
	defer c.Close()

	log.Tracef("TEP command %d: MEI client max message length %d", command, c.Heci.GetBufferSize())

	response, err := c.call(request)
	if err != nil {
		return nil, fmt.Errorf("TEP command %d: %w", command, err)
	}

	status, err := parseResponseHeader(response, CommandFeatureTEP, command)
	if err != nil {
		return nil, fmt.Errorf("TEP command %d: %w", command, err)
	}

	if err := TEPStatus(status).Err(); err != nil {
		return nil, fmt.Errorf("TEP command %d: %w", command, err)
	}

	return response[minResponseSize:], nil
}

// TEPGetCapabilities sends TEP_GET_CAPABILITIES_CMD.
func (c *Command) TEPGetCapabilities() (*TEPCapabilities, error) {
	var req tepEmptyRequest

	req.Header = tepHeader(TEPCommandGetCapabilities, &req)

	payload, err := c.tepCall(TEPCommandGetCapabilities, &req)
	if err != nil {
		return nil, err
	}

	return parseTEPCapabilities(payload)
}

// TEPGetVouchers sends TEP_GET_VOUCHERS_CMD.
func (c *Command) TEPGetVouchers() ([]TEPVoucherID, error) {
	return c.tepGetVoucherIDs(TEPCommandGetVouchers)
}

// TEPGetAllVoucherIDs sends TEP_GET_ALL_VOUCHERS_ID_CMD.
func (c *Command) TEPGetAllVoucherIDs() ([]TEPVoucherID, error) {
	return c.tepGetVoucherIDs(TEPCommandGetAllVoucherIDs)
}

func (c *Command) tepGetVoucherIDs(command uint8) ([]TEPVoucherID, error) {
	var req tepEmptyRequest

	req.Header = tepHeader(command, &req)

	payload, err := c.tepCall(command, &req)
	if err != nil {
		return nil, err
	}

	return parseTEPVoucherIDs(payload)
}

// TEPGetVoucherStateByFeature sends TEP_GET_VOUCHER_STATE_BY_FEATURE_CMD. The
// feature is sent as its INTEL_TEP_OID. With no voucher for the feature, PTL
// CSME 21 answers TEP_INVALID_VOUCHER (ErrTEPInvalidVoucher).
func (c *Command) TEPGetVoucherStateByFeature(feature TEPFeature) (*TEPVoucherState, error) {
	req := tepFeatureRequest{Feature: feature.OID()}
	req.Header = tepHeader(TEPCommandGetVoucherStateByFeature, &req)

	payload, err := c.tepCall(TEPCommandGetVoucherStateByFeature, &req)
	if err != nil {
		return nil, err
	}

	return parseTEPVoucherState(payload)
}

// TEPGetOwnershipState sends TEP_GET_OWNERSHIP_STATE_CMD. reqID is a
// server-chosen random value that CSME echoes and signs to prove freshness.
func (c *Command) TEPGetOwnershipState(reqID TEPNonce, voucherID TEPVoucherID) (*TEPOwnershipState, error) {
	req := tepOwnershipStateRequest{ReqID: reqID, VoucherID: voucherID}
	req.Header = tepHeader(TEPCommandGetOwnershipState, &req)

	payload, err := c.tepCall(TEPCommandGetOwnershipState, &req)
	if err != nil {
		return nil, err
	}

	return parseTEPOwnershipState(payload, reqID)
}

// TEPGetTimeSyncNonce sends TEP_GET_TIME_SYNC_NONCE_CMD. reqID is a
// server-chosen random value that CSME echoes and signs to prove freshness.
func (c *Command) TEPGetTimeSyncNonce(reqID TEPNonce) (*TEPTimeSyncNonce, error) {
	req := tepReqIDRequest{ReqID: reqID}
	req.Header = tepHeader(TEPCommandGetTimeSyncNonce, &req)

	payload, err := c.tepCall(TEPCommandGetTimeSyncNonce, &req)
	if err != nil {
		return nil, err
	}

	return parseTEPTimeSyncNonce(payload, reqID)
}

func errShortPayload(what string, got, want int) error {
	return fmt.Errorf("%w: %s payload is %d bytes, need %d", ErrInvalidResponse, what, got, want)
}

// parseTEPCapabilities decodes max_vouchers u8, num_features u8,
// features_list u8[]. This is the FAS layout, which PTL CSME 21 uses; the
// UPID SDK's num_features/OEMPlatformId[32] layout does not match hardware.
func parseTEPCapabilities(payload []byte) (*TEPCapabilities, error) {
	const fixed = 2

	if len(payload) < fixed {
		return nil, errShortPayload("capabilities", len(payload), fixed)
	}

	numFeatures := int(payload[1])
	list := payload[fixed:]

	if numFeatures > len(list) {
		return nil, errShortPayload("capabilities", len(payload), fixed+numFeatures)
	}

	caps := &TEPCapabilities{
		MaxVouchers: int(payload[0]),
		Features:    make([]TEPFeature, 0, numFeatures),
	}

	for _, f := range list[:numFeatures] {
		caps.Features = append(caps.Features, TEPFeature(f))
	}

	return caps, nil
}

// parseTEPVoucherIDs decodes num_vouchers u32 followed by that many TEP_VOUCHER_IDs.
func parseTEPVoucherIDs(payload []byte) ([]TEPVoucherID, error) {
	if len(payload) < uint32Size {
		return nil, errShortPayload("voucher list", len(payload), uint32Size)
	}

	count := binary.LittleEndian.Uint32(payload)
	ids := payload[uint32Size:]

	if uint64(count)*TEPVoucherIDSize > uint64(len(ids)) {
		return nil, fmt.Errorf("%w: voucher list claims %d vouchers but has %d bytes", ErrInvalidResponse, count, len(ids))
	}

	vouchers := make([]TEPVoucherID, count)
	for i := range vouchers {
		copy(vouchers[i][:], ids[i*TEPVoucherIDSize:])
	}

	return vouchers, nil
}

// parseTEPVoucherState decodes voucher_version u32 followed by TEP_OWNERSHIP_CONTEXT.
func parseTEPVoucherState(payload []byte) (*TEPVoucherState, error) {
	if len(payload) < uint32Size+tepOwnershipContextSize {
		return nil, errShortPayload("voucher state", len(payload), uint32Size+tepOwnershipContextSize)
	}

	state := &TEPVoucherState{VoucherVersion: binary.LittleEndian.Uint32(payload)}

	if err := decodeLE(payload[uint32Size:], &state.Context); err != nil {
		return nil, err
	}

	return state, nil
}

// parseTEPOwnershipState decodes req_id[20], TEP_OWNERSHIP_CONTEXT, CSME_SIGNATURE.
func parseTEPOwnershipState(payload []byte, reqID TEPNonce) (*TEPOwnershipState, error) {
	if err := checkReqID(payload, reqID); err != nil {
		return nil, err
	}

	const sigOffset = TEPNonceSize + tepOwnershipContextSize

	if len(payload) < sigOffset+csmeSignatureFixedSize {
		return nil, errShortPayload("ownership state", len(payload), sigOffset+csmeSignatureFixedSize)
	}

	state := &TEPOwnershipState{}

	if err := decodeLE(payload[TEPNonceSize:], &state.Context); err != nil {
		return nil, err
	}

	sig, err := decodeCSMESignature(payload[sigOffset:])
	if err != nil {
		return nil, err
	}

	state.Signature = sig
	state.SignedData = signedData(payload, sigOffset)

	return state, nil
}

// parseTEPTimeSyncNonce decodes req_id[20], csme_nonce[20], CSME_SIGNATURE.
func parseTEPTimeSyncNonce(payload []byte, reqID TEPNonce) (*TEPTimeSyncNonce, error) {
	const sigOffset = 2 * TEPNonceSize

	if err := checkReqID(payload, reqID); err != nil {
		return nil, err
	}

	if len(payload) < sigOffset+csmeSignatureFixedSize {
		return nil, errShortPayload("time sync nonce", len(payload), sigOffset+csmeSignatureFixedSize)
	}

	nonce := &TEPTimeSyncNonce{}
	copy(nonce.CSMENonce[:], payload[TEPNonceSize:sigOffset])

	sig, err := decodeCSMESignature(payload[sigOffset:])
	if err != nil {
		return nil, err
	}

	nonce.Signature = sig
	nonce.SignedData = signedData(payload, sigOffset)

	return nonce, nil
}

// checkReqID verifies that the payload starts with the req_id that was sent.
func checkReqID(payload []byte, reqID TEPNonce) error {
	if len(payload) < TEPNonceSize {
		return errShortPayload("req_id", len(payload), TEPNonceSize)
	}

	if !bytes.Equal(payload[:TEPNonceSize], reqID[:]) {
		return ErrTEPRequestIDMismatch
	}

	return nil
}

// signedData rebuilds Status || <payload up to the signature> ||
// SignatureMechanism || Timestamp, the order CSME signs in (the reverse of
// the CSME_SIGNATURE field order). Status is always TEP_SUCCESS here, since
// tepCall rejects any other status.
func signedData(payload []byte, sigOffset int) []byte {
	timestamp := payload[sigOffset : sigOffset+uint32Size]
	mechanism := payload[sigOffset+uint32Size : sigOffset+2*uint32Size]

	data := binary.LittleEndian.AppendUint32(nil, uint32(TEPStatusSuccess))
	data = append(data, payload[:sigOffset]...)
	data = append(data, mechanism...)

	return append(data, timestamp...)
}

// decodeCSMESignature decodes a CSME_SIGNATURE. Firmware may omit unused
// trailing certificate bytes, so a short buffer is zero-padded as long as
// the fixed fields are present.
func decodeCSMESignature(b []byte) (CSMESignature, error) {
	var sig CSMESignature

	if len(b) < csmeSignatureFixedSize {
		return sig, errShortPayload("CSME_SIGNATURE", len(b), csmeSignatureFixedSize)
	}

	full := make([]byte, binary.Size(sig))
	copy(full, b)

	if err := decodeLE(full, &sig); err != nil {
		return sig, err
	}

	return sig, nil
}

func decodeLE(b []byte, v any) error {
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	return nil
}
