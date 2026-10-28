/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// These commands change CSME state. The ownership flow is:
//
//  1. TEPGetTimeSyncNonce, then the server obtains OCSP responses for the
//     Ownership Service certificate chain that include the CSME nonce.
//  2. TEPSetTimeAndCerts with that chain and those OCSP responses.
//  3. TEPRequestOwnershipVoucher; the server has the Ownership Service sign it.
//  4. TEPSetOwnershipVoucher with the Ownership Service signed voucher.

var (
	// ErrMessageTooLarge is returned when a request exceeds the MEI client's maximum message length.
	ErrMessageTooLarge = errors.New("request exceeds MEI client maximum message length")
	// ErrTEPInvalidChain is returned when a certificate chain or OCSP response list cannot be encoded.
	ErrTEPInvalidChain = errors.New("invalid TEP certificate chain or OCSP responses")
	// ErrTEPVoucherTooLarge is returned when a CMS voucher exceeds TEPMaxJSONVoucherSize.
	ErrTEPVoucherTooLarge = errors.New("TEP voucher exceeds maximum size")
	// ErrTEPTooManyFeatures is returned when a voucher request lists more than TEPMaxVoucherFeatures features.
	ErrTEPTooManyFeatures = errors.New("too many TEP voucher features")
	// ErrTEPInvalidFeature is returned when a voucher request has no features or lists one that cannot be requested.
	ErrTEPInvalidFeature = errors.New("invalid TEP voucher feature")
	// ErrTEPEmptyVoucher is returned when a voucher request or voucher is missing or empty.
	ErrTEPEmptyVoucher = errors.New("TEP voucher is empty")
)

// nilUUID is the RFC 4122 nil UUID. As a PrevVoucherID it means "no previous voucher".
const nilUUID = "00000000-0000-0000-0000-000000000000"

type (
	tepSetTimeCertsRequest struct {
		Header                UPIDHECIHeader
		LengthOfCertificates  [TEPMaxChainEntries]uint16
		Certificates          [TEPCertChainBufferSize]byte
		LengthOfOCSPResponses [TEPMaxChainEntries]uint16
		OCSPResponses         [TEPCertChainBufferSize]byte
	}
	tepVoucherRequest struct {
		Header  UPIDHECIHeader
		Request TEPBinaryVoucherRequest
	}
	tepSetOwnershipRequest struct {
		Header     UPIDHECIHeader
		VoucherID  TEPVoucherID
		VoucherLen uint32
		Voucher    [TEPMaxJSONVoucherSize]byte
	}
	tepVoucherIDRequest struct {
		Header    UPIDHECIHeader
		VoucherID TEPVoucherID
	}
)

// SetFeatures stores the OIDs of features in the request's feature list. At
// least one feature is required. TEPFeatureAny only appears in stored
// vouchers and is rejected, as is the zero value, which would end the list.
func (r *TEPBinaryVoucherRequest) SetFeatures(features ...TEPFeature) error {
	if len(features) == 0 {
		return fmt.Errorf("%w: at least one feature is required", ErrTEPInvalidFeature)
	}

	if len(features) > TEPMaxVoucherFeatures {
		return fmt.Errorf("%w: %d, at most %d", ErrTEPTooManyFeatures, len(features), TEPMaxVoucherFeatures)
	}

	for _, f := range features {
		if f == 0 || f == TEPFeatureAny {
			return fmt.Errorf("%w: feature %d cannot be requested", ErrTEPInvalidFeature, f)
		}
	}

	r.Features = [TEPMaxVoucherFeatures]TEPOID{}
	for i, f := range features {
		r.Features[i] = f.OID()
	}

	return nil
}

// IsUpdate reports whether the request updates an existing voucher, i.e.
// PrevVoucherID is set and is not the nil UUID.
func (r *TEPBinaryVoucherRequest) IsUpdate() bool {
	return !r.PrevVoucherID.IsZero() && r.PrevVoucherID.String() != nilUUID
}

// TEPSetTimeAndCerts sends TEP_SET_TIME_CERTS_CMD with the Ownership Service
// certificate chain (leaf first, DER) and the OCSP response for each
// certificate, which must carry the nonce from TEPGetTimeSyncNonce. CSME uses
// them to set TEP time and cache the certificates' revocation status for 24 hours.
func (c *Command) TEPSetTimeAndCerts(certChain, ocspResponses [][]byte) error {
	var req tepSetTimeCertsRequest

	if err := joinChain("certificate chain", certChain, req.LengthOfCertificates[:], req.Certificates[:]); err != nil {
		return err
	}

	if err := joinChain("OCSP responses", ocspResponses, req.LengthOfOCSPResponses[:], req.OCSPResponses[:]); err != nil {
		return err
	}

	req.Header = tepHeader(TEPCommandSetTimeCerts, &req)

	_, err := c.tepCall(TEPCommandSetTimeCerts, &req)

	return err
}

// TEPRequestOwnershipVoucher sends TEP_OWNERSHIP_VOUCHER_REQUEST_CMD, or
// TEP_OWNERSHIP_VOUCHER_UPDATE_REQUEST_CMD when request.IsUpdate(). It returns
// the CSME-signed JSON voucher in CMS (DER) form for the Ownership Service to
// re-sign. TEPSetTimeAndCerts must have been called first. A zero Format is
// sent as TEPVoucherFormatCMSJSON.
func (c *Command) TEPRequestOwnershipVoucher(request *TEPBinaryVoucherRequest) ([]byte, error) {
	if request == nil {
		return nil, fmt.Errorf("%w: nil voucher request", ErrTEPEmptyVoucher)
	}

	command := TEPCommandOwnershipVoucherRequest
	if request.IsUpdate() {
		command = TEPCommandOwnershipVoucherUpdateRequest
	}

	req := tepVoucherRequest{Request: *request}
	if req.Request.Format == 0 {
		req.Request.Format = TEPVoucherFormatCMSJSON
	}

	req.Header = tepHeader(command, &req)

	payload, err := c.tepCall(command, &req)
	if err != nil {
		return nil, err
	}

	return parseTEPVoucherCMS(payload)
}

// TEPSetOwnershipVoucher sends TEP_SET_OWNERSHIP_CMD with the voucher (CMS,
// DER) as re-signed by the Ownership Service. The CMS must carry only the
// Ownership Service leaf certificate.
func (c *Command) TEPSetOwnershipVoucher(voucherID TEPVoucherID, voucherCMS []byte) error {
	if len(voucherCMS) == 0 {
		return ErrTEPEmptyVoucher
	}

	if len(voucherCMS) > TEPMaxJSONVoucherSize {
		return fmt.Errorf("%w: %d bytes, at most %d", ErrTEPVoucherTooLarge, len(voucherCMS), TEPMaxJSONVoucherSize)
	}

	req := tepSetOwnershipRequest{VoucherID: voucherID, VoucherLen: uint32(len(voucherCMS))}
	copy(req.Voucher[:], voucherCMS)
	req.Header = tepHeader(TEPCommandSetOwnership, &req)

	_, err := c.tepCall(TEPCommandSetOwnership, &req)

	return err
}

// TEPRemoveOwnershipVoucher sends TEP_OWNERSHIP_REMOVE_CMD. CSME only removes
// vouchers that are not ACTIVE (TEP_NOT_ALLOWED otherwise).
func (c *Command) TEPRemoveOwnershipVoucher(voucherID TEPVoucherID) error {
	req := tepVoucherIDRequest{VoucherID: voucherID}
	req.Header = tepHeader(TEPCommandOwnershipRemove, &req)

	_, err := c.tepCall(TEPCommandOwnershipRemove, &req)

	return err
}

// parseTEPVoucherCMS decodes voucher_request_len u32 followed by the CMS
// bytes. A successful response must carry a non-empty voucher request.
func parseTEPVoucherCMS(payload []byte) ([]byte, error) {
	if len(payload) < uint32Size {
		return nil, errShortPayload("voucher request", len(payload), uint32Size)
	}

	n := binary.LittleEndian.Uint32(payload)
	if n == 0 {
		return nil, fmt.Errorf("%w: empty voucher request", ErrInvalidResponse)
	}

	if n > TEPMaxJSONVoucherSize || int(n) > len(payload)-uint32Size {
		return nil, fmt.Errorf("%w: voucher request length %d exceeds %d-byte payload", ErrInvalidResponse, n, len(payload)-uint32Size)
	}

	return append([]byte(nil), payload[uint32Size:uint32Size+int(n)]...), nil
}

// joinChain concatenates entries into buf and records each length, the
// inverse of splitChain.
func joinChain(what string, entries [][]byte, lengths []uint16, buf []byte) error {
	if len(entries) == 0 || len(entries) > len(lengths) {
		return fmt.Errorf("%w: %s has %d entries, want 1 to %d", ErrTEPInvalidChain, what, len(entries), len(lengths))
	}

	offset := 0

	for i, e := range entries {
		if len(e) == 0 || len(e) > math.MaxUint16 || offset+len(e) > len(buf) {
			return fmt.Errorf("%w: %s entry %d (%d bytes) does not fit in %d-byte buffer", ErrTEPInvalidChain, what, i, len(e), len(buf))
		}

		lengths[i] = uint16(len(e))
		offset += copy(buf[offset:], e)
	}

	return nil
}
