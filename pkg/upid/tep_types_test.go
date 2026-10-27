/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"crypto/x509/pkix"
	"encoding/asn1"
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
	assert.Equal(t, "domain-ca-cert", TEPCredentialTypeDomainCA.String())
	assert.Equal(t, "cap-mgmt", TEPCredentialTypeCapMgmt.String())
	assert.Equal(t, "SHA-384", TEPHashSHA384.String())
	assert.Equal(t, "active", TEPOwnershipActive.String())
	assert.Equal(t, "update", TEPOwnershipUpdate.String())
	assert.Equal(t, "undefined", TEPOwnershipNotSet.String())
	assert.Equal(t, "1.0", TEPVoucherVersion1.String())
	assert.Equal(t, "unknown(9)", TEPOwnershipStatus(9).String())
}

func TestTEPHashAlgorithmSize(t *testing.T) {
	assert.Equal(t, 32, TEPHashSHA256.Size())
	assert.Equal(t, 48, TEPHashSHA384.Size())
	assert.Equal(t, 64, TEPHashSHA512.Size())
	assert.Equal(t, 28, TEPHashSHA224.Size())
	assert.Equal(t, 0, TEPHashAlgorithm(1).Size())
	assert.Equal(t, 0, TEPHashNone.Size())
	assert.Equal(t, "SHA-384", TEPHashSHA384.String())
}

func TestNewTEPPolicyConfigAttr(t *testing.T) {
	attr, err := NewTEPPolicyConfigAttr(16)
	require.NoError(t, err)

	// hash_algo_byte = none (0), len = TEP_CONFIG_LENGTH_16_BYTE (2) in byte 1.
	assert.Equal(t, TEPHashAlgorithm(0x0200), attr)
	assert.Equal(t, TEPHashNone, attr.Algorithm())
	assert.Equal(t, 16, attr.Size())
	assert.Equal(t, "none", attr.String())

	for _, bad := range []int{0, 7, 12, 72} {
		_, err := NewTEPPolicyConfigAttr(bad)
		require.ErrorIs(t, err, ErrInvalidPolicyConfigLength, "length %d", bad)
	}

	// Lengths above 64 read from firmware are clamped.
	assert.Equal(t, 64, TEPHashAlgorithm(0x0F00).Size())
}

func TestTEPOwnershipContextHelpers(t *testing.T) {
	issuer := pkix.Name{CommonName: "TEP Ownership Voucher Service", Organization: []string{"Intel Corporation"}, Country: []string{"US"}}
	issuerDER, err := asn1.Marshal(issuer.ToRDNSequence())
	require.NoError(t, err)

	var c TEPOwnershipContext

	copy(c.IssuerSubjectDN[:], issuerDER)
	copy(c.CertSerialNumber[:], []byte{0x01, 0x02, 0x00, 0x00})
	c.Features[0] = TEPFeatureAMT.OID()
	c.CertPolicies[0] = TEPOID{X: 5, Y: TEPPolicyVettedClaimed}
	c.HashAlgorithm = TEPHashSHA384
	c.OwnerCredentialHash[47] = 0xFF

	name, err := c.IssuerName()
	require.NoError(t, err)
	assert.Equal(t, "CN=TEP Ownership Voucher Service,O=Intel Corporation,C=US", name.String())

	subject, err := c.SubjectName()
	require.NoError(t, err)
	assert.Empty(t, subject.String(), "all-zero DN is an empty name")

	assert.Equal(t, "258", c.SerialNumber().String(), "0x0102 with trailing zero padding trimmed")
	assert.Equal(t, []TEPOID{TEPFeatureAMT.OID()}, c.FeatureOIDs())
	assert.Equal(t, []TEPOID{{X: 5, Y: 6}}, c.PolicyOIDs())
	assert.Equal(t, TEPVoucherVersion1, c.VoucherVersion())
	assert.Len(t, c.Credential(), 48)

	c.Features[0] = TEPFeatureCapMgmt.OID()
	assert.Equal(t, TEPVoucherVersion2, c.VoucherVersion())

	c.CertSubjectDN[0] = 0x30
	c.CertSubjectDN[1] = 0x05
	_, err = c.SubjectName()
	require.ErrorIs(t, err, ErrInvalidDN)
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
