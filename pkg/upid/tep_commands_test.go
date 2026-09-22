/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"encoding/binary"
	"errors"
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
		Features:        [TEPMaxVoucherFeatures]TEPFeature{TEPFeatureAMT},
		OEMID:           0x8086,
	}
}

func testSignature() CSMESignature {
	sig := CSMESignature{Timestamp: 1_700_000_000, SignatureMechanism: TEPSignatureECDSA384SHA384}
	sig.Signature[0] = 0xAA
	sig.LengthOfCertificates[0] = 3
	copy(sig.Certificates[:], []byte{0x30, 0x01, 0x00})

	return sig
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

		resp := tepResponse(TEPCommandGetCapabilities, TEPStatusSuccess, make([]byte, 33))
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

func TestTEPGetCapabilities(t *testing.T) {
	payload := make([]byte, 1+OEMPlatformIDSize+20)
	payload[0] = 1
	payload[1] = 0xEE
	payload[1+OEMPlatformIDSize] = byte(TEPFeatureAMT)

	var sent []byte

	cmd := &Command{Heci: tepMock(tepResponse(TEPCommandGetCapabilities, TEPStatusSuccess, payload), &sent)}

	caps, err := cmd.TEPGetCapabilities()
	require.NoError(t, err)

	assert.Equal(t, []byte{CommandFeatureTEP, TEPCommandGetCapabilities, 0, 0}, sent)
	assert.Equal(t, []TEPFeature{TEPFeatureAMT}, caps.Features)
	assert.True(t, caps.Supports(TEPFeatureAMT))
	assert.False(t, caps.Supports(TEPFeatureOEM1))
	assert.Equal(t, byte(0xEE), caps.OEMPlatformID[0])

	t.Run("num_features exceeds list", func(t *testing.T) {
		_, err := parseTEPCapabilities(append([]byte{2}, make([]byte, OEMPlatformIDSize+1)...))
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

	assert.Equal(t, []byte{CommandFeatureTEP, TEPCommandGetVoucherStateByFeature, 4, 0, 101, 0, 0, 0}, sent)
	assert.Equal(t, uint32(7), state.VoucherVersion)
	assert.Equal(t, ctx, state.Context)

	t.Run("short", func(t *testing.T) {
		_, err := parseTEPVoucherState(payload[:100])
		require.ErrorIs(t, err, ErrInvalidResponse)
	})
}

func TestTEPGetOwnershipState(t *testing.T) {
	ctx := testContext()
	sig := testSignature()
	sigBytes := encode(t, &sig)
	ctxBytes := encode(t, &ctx)

	id := ctx.VoucherID

	for _, tc := range []struct {
		name    string
		padding int
	}{
		{"packed", 0},
		{"aligned", tepOwnershipContextPadding},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			payload := append([]byte(nil), testReqID[:]...)
			payload = append(payload, ctxBytes...)
			payload = append(payload, make([]byte, tc.padding)...)
			payload = append(payload, sigBytes...)
			payload = append(payload, make([]byte, tc.padding)...)

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

			sigOffset := TEPNonceSize + tepOwnershipContextSize + tc.padding
			wantSigned := append([]byte{0, 0, 0, 0}, payload[:sigOffset]...)
			wantSigned = append(wantSigned, sigBytes[:csmeSignatureSignedFieldsSize]...)
			assert.Equal(t, wantSigned, state.SignedData)
		})
	}

	t.Run("request ID mismatch", func(t *testing.T) {
		payload := make([]byte, TEPNonceSize+tepOwnershipContextSize+len(sigBytes))

		var sent []byte

		cmd := &Command{Heci: tepMock(tepResponse(TEPCommandGetOwnershipState, TEPStatusSuccess, payload), &sent)}

		_, err := cmd.TEPGetOwnershipState(testReqID, id)
		require.ErrorIs(t, err, ErrTEPRequestIDMismatch)
	})
}

func TestTEPGetTimeSyncNonce(t *testing.T) {
	sig := testSignature()
	sigBytes := encode(t, &sig)
	csmeNonce := TEPNonce{0xC5}

	payload := append([]byte(nil), testReqID[:]...)
	payload = append(payload, csmeNonce[:]...)
	payload = append(payload, sigBytes...)

	var sent []byte

	cmd := &Command{Heci: tepMock(tepResponse(TEPCommandGetTimeSyncNonce, TEPStatusSuccess, payload), &sent)}

	nonce, err := cmd.TEPGetTimeSyncNonce(testReqID)
	require.NoError(t, err)

	assert.Equal(t, append([]byte{CommandFeatureTEP, TEPCommandGetTimeSyncNonce, 20, 0}, testReqID[:]...), sent)
	assert.Equal(t, csmeNonce, nonce.CSMENonce)
	assert.Equal(t, sig, nonce.Signature)

	chain, err := nonce.Signature.CertificateChain()
	require.NoError(t, err)
	assert.Equal(t, [][]byte{{0x30, 0x01, 0x00}}, chain)

	wantSigned := append([]byte{0, 0, 0, 0}, payload[:2*TEPNonceSize]...)
	wantSigned = append(wantSigned, sigBytes[:csmeSignatureSignedFieldsSize]...)
	assert.Equal(t, wantSigned, nonce.SignedData)

	t.Run("trimmed certificate buffer is accepted", func(t *testing.T) {
		trimmed := payload[:2*TEPNonceSize+csmeSignatureFixedSize+3]

		got, err := parseTEPTimeSyncNonce(trimmed, testReqID)
		require.NoError(t, err)
		assert.Equal(t, sig, got.Signature)
	})

	t.Run("signature fixed fields missing", func(t *testing.T) {
		_, err := parseTEPTimeSyncNonce(payload[:2*TEPNonceSize+10], testReqID)
		require.ErrorIs(t, err, ErrInvalidResponse)
	})
}
