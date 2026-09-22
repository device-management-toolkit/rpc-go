/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testReqID = TEPNonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

// tepResponse builds a TEP response: header, status, payload.
func tepResponse(command uint8, status TEPStatus, payload []byte) []byte {
	resp := []byte{CommandFeatureTEP, command, 0, 0}
	binary.LittleEndian.PutUint16(resp[2:], uint16(uint32Size+len(payload)))
	resp = binary.LittleEndian.AppendUint32(resp, uint32(status))

	return append(resp, payload...)
}

// tepMock returns a mock that records the request and replies with response.
func tepMock(response []byte, sent *[]byte) *MockHECI {
	return &MockHECI{
		bufferSize: 16 * 1024,
		sendMessageFunc: func(buffer []byte, _ *uint32) (int, error) {
			*sent = append([]byte(nil), buffer...)

			return len(buffer), nil
		},
		receiveMessageFunc: respondWith(response),
	}
}

func encode(t *testing.T, v any) []byte {
	t.Helper()

	b, err := binary.Append(nil, binary.LittleEndian, v)
	require.NoError(t, err)

	return b
}

func testContext() TEPOwnershipContext {
	id, _ := NewTEPVoucherID("932586c2-d439-4154-86cb-49ba914aa716")

	return TEPOwnershipContext{
		OwnershipStatus: TEPOwnershipActive,
		VoucherID:       id,
		Assertion:       TEPAssertionVettedClaimed,
		HashAlgorithm:   TEPHashSHA384,
		Features:        [TEPMaxVoucherFeatures]TEPOID{TEPFeatureAMT.OID()},
		OEMID:           0x8086,
	}
}

func TestTEPCall(t *testing.T) {
	t.Run("maps TEP status", func(t *testing.T) {
		var sent []byte

		cmd := &Command{Heci: tepMock(tepResponse(TEPCommandGetCapabilities, TEPStatusTimeNotSet, nil), &sent)}

		_, err := cmd.TEPGetCapabilities()
		require.ErrorIs(t, err, ErrTEPTimeNotSet)
	})

	t.Run("rejects platform ID feature in response", func(t *testing.T) {
		var sent []byte

		resp := tepResponse(TEPCommandGetCapabilities, TEPStatusSuccess, []byte{3, 1, 0x65})
		resp[0] = CommandFeaturePlatformID

		cmd := &Command{Heci: tepMock(resp, &sent)}

		_, err := cmd.TEPGetCapabilities()
		require.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("MEI client not available", func(t *testing.T) {
		m := &MockHECI{initWithGUIDFunc: func(any) error { return errors.New("no device") }}

		_, err := (&Command{Heci: m}).TEPGetCapabilities()
		require.ErrorIs(t, err, ErrUPIDNotSupported)
	})

	t.Run("closes the MEI client", func(t *testing.T) {
		var sent []byte

		m := tepMock(tepResponse(TEPCommandGetCapabilities, TEPStatusInternalError, nil), &sent)

		_, err := (&Command{Heci: m}).TEPGetCapabilities()
		require.ErrorIs(t, err, ErrTEPInternalError)
		assert.True(t, m.closed)
	})
}

// signCSME returns a CSME_SIGNATURE over Status(0) || data made the way PTL
// CSME 21 signs (SHA-384 over ... || mechanism || timestamp, raw big-endian
// r || s), using a throwaway P-384 key with a self-signed leaf certificate.
func signCSME(t *testing.T, data []byte, timestamp uint32) CSMESignature {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	sig := CSMESignature{Timestamp: timestamp, SignatureMechanism: TEPSignatureECDSA384SHA384}
	sig.LengthOfCertificates[0] = uint16(len(der))
	copy(sig.Certificates[:], der)

	signed := binary.LittleEndian.AppendUint32(nil, uint32(TEPStatusSuccess))
	signed = append(signed, data...)
	signed = binary.LittleEndian.AppendUint32(signed, uint32(sig.SignatureMechanism))
	signed = binary.LittleEndian.AppendUint32(signed, sig.Timestamp)

	digest := sha512.Sum384(signed)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)

	r.FillBytes(sig.Signature[:p384ScalarSize])
	s.FillBytes(sig.Signature[p384ScalarSize : 2*p384ScalarSize])

	return sig
}

func TestTEPGetCapabilities(t *testing.T) {
	// Response captured from PTL CSME 21: max_vouchers=3, num_features=2, [101, 150], pad.
	payload := []byte{0x03, 0x02, 0x65, 0x96, 0x00}

	var sent []byte

	cmd := &Command{Heci: tepMock(tepResponse(TEPCommandGetCapabilities, TEPStatusSuccess, payload), &sent)}

	caps, err := cmd.TEPGetCapabilities()
	require.NoError(t, err)

	assert.Equal(t, []byte{CommandFeatureTEP, TEPCommandGetCapabilities, 0, 0}, sent)
	assert.Equal(t, 3, caps.MaxVouchers)
	assert.Equal(t, []TEPFeature{TEPFeatureAMT, TEPFeatureOEM1}, caps.Features)
	assert.True(t, caps.Supports(TEPFeatureAMT))
	assert.False(t, caps.Supports(TEPFeature(1)))

	t.Run("num_features exceeds list", func(t *testing.T) {
		_, err := parseTEPCapabilities([]byte{3, 2, 0x65})
		require.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("too short", func(t *testing.T) {
		_, err := parseTEPCapabilities([]byte{3})
		require.ErrorIs(t, err, ErrInvalidResponse)
	})
}

func TestTEPGetVoucherIDs(t *testing.T) {
	id, err := NewTEPVoucherID("9f8968c2-572d-4560-ae77-fabb77b78198")
	require.NoError(t, err)

	payload := binary.LittleEndian.AppendUint32(nil, 1)
	payload = append(payload, id[:]...)

	for _, tc := range []struct {
		name    string
		command uint8
		get     func(*Command) ([]TEPVoucherID, error)
	}{
		{"TEP_GET_VOUCHERS", TEPCommandGetVouchers, (*Command).TEPGetVouchers},
		{"TEP_GET_ALL_VOUCHERS_ID", TEPCommandGetAllVoucherIDs, (*Command).TEPGetAllVoucherIDs},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var sent []byte

			cmd := &Command{Heci: tepMock(tepResponse(tc.command, TEPStatusSuccess, payload), &sent)}

			ids, err := tc.get(cmd)
			require.NoError(t, err)
			assert.Equal(t, []TEPVoucherID{id}, ids)
			assert.Equal(t, []byte{CommandFeatureTEP, tc.command, 0, 0}, sent)
		})
	}

	t.Run("no vouchers", func(t *testing.T) {
		ids, err := parseTEPVoucherIDs(binary.LittleEndian.AppendUint32(nil, 0))
		require.NoError(t, err)
		assert.Empty(t, ids)
	})

	t.Run("count exceeds payload", func(t *testing.T) {
		_, err := parseTEPVoucherIDs(binary.LittleEndian.AppendUint32(nil, 2))
		require.ErrorIs(t, err, ErrInvalidResponse)
	})
}

func TestTEPGetVoucherStateByFeature(t *testing.T) {
	ctx := testContext()
	payload := binary.LittleEndian.AppendUint32(nil, 7)
	payload = append(payload, encode(t, &ctx)...)

	var sent []byte

	cmd := &Command{Heci: tepMock(tepResponse(TEPCommandGetVoucherStateByFeature, TEPStatusSuccess, payload), &sent)}

	state, err := cmd.TEPGetVoucherStateByFeature(TEPFeatureAMT)
	require.NoError(t, err)

	// Feature is sent as INTEL_TEP_OID {x=5, y=101}.
	assert.Equal(t, []byte{CommandFeatureTEP, TEPCommandGetVoucherStateByFeature, 4, 0, 5, 0, 101, 0}, sent)
	assert.Equal(t, uint32(7), state.VoucherVersion)
	assert.Equal(t, ctx, state.Context)

	t.Run("short", func(t *testing.T) {
		_, err := parseTEPVoucherState(payload[:100])
		require.ErrorIs(t, err, ErrInvalidResponse)
	})
}

func TestTEPGetOwnershipState(t *testing.T) {
	ctx := testContext()
	ctxBytes := encode(t, &ctx)
	id := ctx.VoucherID

	data := append(append([]byte(nil), testReqID[:]...), ctxBytes...)
	sig := signCSME(t, data, 1_700_000_000)

	payload := append(append([]byte(nil), data...), encode(t, &sig)...)

	var sent []byte

	cmd := &Command{Heci: tepMock(tepResponse(TEPCommandGetOwnershipState, TEPStatusSuccess, payload), &sent)}

	state, err := cmd.TEPGetOwnershipState(testReqID, id)
	require.NoError(t, err)

	require.Len(t, sent, headerSize+TEPNonceSize+TEPVoucherIDSize)
	assert.Equal(t, []byte{CommandFeatureTEP, TEPCommandGetOwnershipState, 56, 0}, sent[:headerSize])
	assert.Equal(t, testReqID[:], sent[headerSize:headerSize+TEPNonceSize])
	assert.Equal(t, id[:], sent[headerSize+TEPNonceSize:])

	assert.Equal(t, ctx, state.Context)
	assert.Equal(t, sig, state.Signature)
	require.NoError(t, state.Signature.Verify(state.SignedData))

	t.Run("request ID mismatch", func(t *testing.T) {
		bad := append([]byte(nil), payload...)
		bad[0] ^= 0xFF

		var sent []byte

		cmd := &Command{Heci: tepMock(tepResponse(TEPCommandGetOwnershipState, TEPStatusSuccess, bad), &sent)}

		_, err := cmd.TEPGetOwnershipState(testReqID, id)
		require.ErrorIs(t, err, ErrTEPRequestIDMismatch)
	})

	t.Run("tampered context fails verification", func(t *testing.T) {
		tampered := append([]byte(nil), payload...)
		tampered[TEPNonceSize] ^= 0xFF

		got, err := parseTEPOwnershipState(tampered, testReqID)
		require.NoError(t, err)
		require.ErrorIs(t, got.Signature.Verify(got.SignedData), ErrCSMESignatureInvalid)
	})
}

func TestTEPGetTimeSyncNonce(t *testing.T) {
	csmeNonce := TEPNonce{0xC5}
	data := append(append([]byte(nil), testReqID[:]...), csmeNonce[:]...)

	// Timestamp 0 (TEP time not set), as seen on hardware before time sync.
	sig := signCSME(t, data, 0)
	sigBytes := encode(t, &sig)
	payload := append(append([]byte(nil), data...), sigBytes...)

	var sent []byte

	cmd := &Command{Heci: tepMock(tepResponse(TEPCommandGetTimeSyncNonce, TEPStatusSuccess, payload), &sent)}

	nonce, err := cmd.TEPGetTimeSyncNonce(testReqID)
	require.NoError(t, err)

	assert.Equal(t, append([]byte{CommandFeatureTEP, TEPCommandGetTimeSyncNonce, 20, 0}, testReqID[:]...), sent)
	assert.Equal(t, csmeNonce, nonce.CSMENonce)
	assert.Equal(t, sig, nonce.Signature)
	require.NoError(t, nonce.Signature.Verify(nonce.SignedData))

	// SignedData ends with mechanism then timestamp, the reverse of the struct order.
	tail := nonce.SignedData[len(nonce.SignedData)-2*uint32Size:]
	assert.Equal(t, []byte{3, 0, 0, 0, 0, 0, 0, 0}, tail)

	t.Run("trimmed certificate buffer is accepted", func(t *testing.T) {
		certLen := int(sig.LengthOfCertificates[0])
		trimmed := payload[:2*TEPNonceSize+csmeSignatureFixedSize+certLen]

		got, err := parseTEPTimeSyncNonce(trimmed, testReqID)
		require.NoError(t, err)
		assert.Equal(t, sig, got.Signature)
		require.NoError(t, got.Signature.Verify(got.SignedData))
	})

	t.Run("signature fixed fields missing", func(t *testing.T) {
		_, err := parseTEPTimeSyncNonce(payload[:2*TEPNonceSize+10], testReqID)
		require.ErrorIs(t, err, ErrInvalidResponse)
	})
}

func TestCSMESignatureVerify(t *testing.T) {
	data := []byte("signed payload")
	sig := signCSME(t, data, 42)
	signed := append(binary.LittleEndian.AppendUint32(nil, 0), data...)
	signed = append(signed, 3, 0, 0, 0, 42, 0, 0, 0)

	require.NoError(t, sig.Verify(signed))

	t.Run("struct order (timestamp first) does not verify", func(t *testing.T) {
		wrong := append(binary.LittleEndian.AppendUint32(nil, 0), data...)
		wrong = append(wrong, 42, 0, 0, 0, 3, 0, 0, 0)
		require.ErrorIs(t, sig.Verify(wrong), ErrCSMESignatureInvalid)
	})

	t.Run("unsupported mechanism", func(t *testing.T) {
		bad := sig
		bad.SignatureMechanism = 0
		require.ErrorIs(t, bad.Verify(signed), ErrCSMESignatureInvalid)
	})

	t.Run("no certificates", func(t *testing.T) {
		bad := sig
		bad.LengthOfCertificates = [CSMESignatureMaxCerts]uint16{}
		require.ErrorIs(t, bad.Verify(signed), ErrCSMESignatureInvalid)
	})
}
