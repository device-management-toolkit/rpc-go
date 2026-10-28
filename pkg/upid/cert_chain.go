/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import "fmt"

// CertIndex selects which CSME key's certificate chain to return (UPID_CERT_IDX).
type CertIndex uint32

const (
	CertIndexBIOS CertIndex = 0
	CertIndexOS   CertIndex = 1
	// CertIndexTEP is the chain of the CSME TEP IDevID key that signs TEP responses.
	CertIndexTEP CertIndex = 2
)

type fullCertChainRequest struct {
	Header    UPIDHECIHeader
	CertIndex CertIndex
}

// GetFullCertificateChain sends UPID_HECI_OEM_PLATFORM_ID_GET_FULL_CERTIFICATE_CHAIN
// and returns the CSME on-die CA (ODCA) certificate chain for the given key,
// DER-encoded, leaf first. It lets a server without internet access validate
// CSME signatures up to the Intel root. Like GetUPID, it enables the UPID
// feature for the call (the firmware answers UPID_STATUS_INVALID_STATE
// otherwise).
func (c *Command) GetFullCertificateChain(index CertIndex) ([][]byte, error) {
	var chain [][]byte

	err := c.withFeatureEnabled(func() error {
		var err error

		chain, err = c.getFullCertificateChain(index)

		return err
	})

	return chain, err
}

func (c *Command) getFullCertificateChain(index CertIndex) ([][]byte, error) {
	// The request carries a UINT32 cert_idx. PTL firmware rejects the request
	// with UPID_STATUS_INVALID_INPUT_PARAMETER when it is missing.
	req := fullCertChainRequest{
		Header:    UPIDHECIHeader{Feature: CommandFeaturePlatformID, Command: CommandOEMPlatformIDGetFullCertChain, ByteCount: 4},
		CertIndex: index,
	}

	response, err := c.call(&req)
	if err != nil {
		return nil, fmt.Errorf("get full certificate chain: %w", err)
	}

	status, err := parseResponseHeader(response, CommandFeaturePlatformID, CommandOEMPlatformIDGetFullCertChain)
	if err != nil {
		return nil, fmt.Errorf("get full certificate chain: %w", err)
	}

	if status != uint32(StatusSuccess) {
		return nil, fmt.Errorf("get full certificate chain: %w", mapStatusError(status))
	}

	return parseFullCertChain(response[minResponseSize:])
}

// parseFullCertChain decodes cert_full_lengths u16[7] followed by cert_full_chain[6000].
func parseFullCertChain(payload []byte) ([][]byte, error) {
	var lengths [CSMESignatureMaxCerts]uint16

	const lengthsSize = 2 * CSMESignatureMaxCerts

	if len(payload) < lengthsSize {
		return nil, errShortPayload("full certificate chain", len(payload), lengthsSize)
	}

	if err := decodeLE(payload[:lengthsSize], &lengths); err != nil {
		return nil, err
	}

	chain, err := splitChain(lengths[:], payload[lengthsSize:])
	if err != nil {
		return nil, err
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: full certificate chain has no certificates", ErrInvalidResponse)
	}

	// Copy out so callers do not hold on to the receive buffer.
	out := make([][]byte, len(chain))
	for i, cert := range chain {
		out[i] = append([]byte(nil), cert...)
	}

	return out, nil
}
