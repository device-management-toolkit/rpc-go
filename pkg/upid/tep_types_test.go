/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTEPWireSizes(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want int
	}{
		{"TEP_BINARY_VOUCHER_REQUEST", TEPBinaryVoucherRequest{}, 564},
		{"TEP_OWNERSHIP_CONTEXT (packed)", TEPOwnershipContext{}, 1138},
		{"CSME_SIGNATURE (packed)", CSMESignature{}, 6534},
		{"TEP_VOUCHER_ID", TEPVoucherID{}, TEPVoucherIDSize},
		{"VERSION", TEPVersion{}, 4},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, binary.Size(tt.v))
		})
	}
}

func TestTEPBinaryVoucherRequestLayout(t *testing.T) {
	id, err := NewTEPVoucherID("932586c2-d439-4154-86cb-49ba914aa716")
	require.NoError(t, err)

	req := TEPBinaryVoucherRequest{
		Format:        TEPVoucherFormatCMSJSON,
		Version:       TEPVersion{Major: 1, Minor: 0},
		VoucherID:     id,
		Assertion:     TEPAssertionVettedClaimed,
		HashAlgorithm: TEPHashSHA384,
		Features:      [TEPMaxVoucherFeatures]TEPOID{TEPFeatureAMT.OID()},
	}

	buf, err := binary.Append(nil, binary.LittleEndian, &req)
	require.NoError(t, err)

	assert.Equal(t, uint32(TEPVoucherFormatCMSJSON), binary.LittleEndian.Uint32(buf[0:4]))
	assert.Equal(t, uint16(1), binary.LittleEndian.Uint16(buf[4:6]), "major version is first")
	assert.Equal(t, "932586c2-d439-4154-86cb-49ba914aa716", string(buf[8:44]))
	assert.Equal(t, uint32(TEPAssertionVettedClaimed), binary.LittleEndian.Uint32(buf[44:48]))
	// format+version+id+assertion+owner+metadata+created+expires+upid+credtype = 416
	assert.Equal(t, uint32(TEPHashSHA384), binary.LittleEndian.Uint32(buf[416:420]))
	// features are the last 40 bytes, as INTEL_TEP_OID {x=5, y=101}
	assert.Equal(t, []byte{5, 0, 101, 0}, buf[524:528])
}

func TestTEPStatusErr(t *testing.T) {
	require.NoError(t, TEPStatusSuccess.Err())

	for status, want := range tepStatusErrors {
		require.ErrorIs(t, status.Err(), want, "status %d", status)
	}

	require.ErrorIs(t, TEPStatus(0x107).Err(), ErrTEPUnknownStatus)
	assert.Contains(t, TEPStatus(0x107).Err().Error(), "0x00000107")
}

func TestTEPStatusValues(t *testing.T) {
	// Values from UPID_TEP_STATUS in the UPID Attestation SDK.
	assert.Equal(t, TEPStatus(0), TEPStatusSuccess)
	assert.Equal(t, TEPStatus(1), TEPStatusTimeNotSet)
	assert.Equal(t, TEPStatus(6), TEPStatusInternalError)
	assert.Equal(t, TEPStatus(11), TEPStatusInvalidCMS)
	assert.Len(t, tepStatusErrors, 11)
}

func TestNewTEPVoucherID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid", "9f8968c2-572d-4560-ae77-fabb77b78198", false},
		{"too short", "9f8968c2", true},
		{"urn form", "urn:uuid:9f8968c2-572d-4560-ae77-fab", true},
		{"no dashes padded", "9f8968c2572d4560ae77fabb77b78198xxxx", true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewTEPVoucherID(tt.id)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrInvalidVoucherID)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.id, v.String())
			assert.False(t, v.IsZero())
		})
	}
}

func TestTEPVoucherIDString(t *testing.T) {
	var v TEPVoucherID

	assert.True(t, v.IsZero())
	assert.Empty(t, v.String())
}

func TestTEPEnumStrings(t *testing.T) {
	assert.Equal(t, "vetted-claimed", TEPAssertionVettedClaimed.String())
	assert.Equal(t, "verified", TEPAssertionVerified.String())
	assert.Equal(t, "domain-ca", TEPCredentialTypeDomainCA.String())
	assert.Equal(t, "SHA-384", TEPHashSHA384.String())
	assert.Equal(t, "ACTIVE", TEPOwnershipActive.String())
	assert.Equal(t, "UPDATE_REQUESTED", TEPOwnershipUpdateRequested.String())
	assert.Equal(t, "unknown(9)", TEPOwnershipStatus(9).String())
}

func TestTEPHashAlgorithmSize(t *testing.T) {
	assert.Equal(t, 32, TEPHashSHA256.Size())
	assert.Equal(t, 48, TEPHashSHA384.Size())
	assert.Equal(t, 64, TEPHashSHA512.Size())
	assert.Equal(t, 0, TEPHashAlgorithm(4).Size())
}

func TestCSMESignatureCertificateChain(t *testing.T) {
	var sig CSMESignature

	copy(sig.Certificates[:], []byte{1, 1, 1, 2, 2})
	sig.LengthOfCertificates[0] = 3
	sig.LengthOfCertificates[1] = 2

	chain, err := sig.CertificateChain()
	require.NoError(t, err)
	assert.Equal(t, [][]byte{{1, 1, 1}, {2, 2}}, chain)

	t.Run("empty", func(t *testing.T) {
		chain, err := (&CSMESignature{}).CertificateChain()
		require.NoError(t, err)
		assert.Empty(t, chain)
	})

	t.Run("overrun", func(t *testing.T) {
		bad := CSMESignature{}
		bad.LengthOfCertificates[0] = TEPCertChainBufferSize
		bad.LengthOfCertificates[1] = 1

		_, err := bad.CertificateChain()
		require.ErrorIs(t, err, ErrInvalidCertChain)
	})
}

func TestTEPFeatureOID(t *testing.T) {
	oid := TEPFeatureAMT.OID()

	assert.Equal(t, TEPOID{X: 5, Y: 101}, oid)
	assert.Equal(t, "2.16.840.1.113741.1.2.5.101", oid.String())
	assert.Equal(t, 4, binary.Size(oid))
	assert.False(t, oid.IsZero())
	assert.True(t, TEPOID{}.IsZero())
}
