/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustVoucherID(t *testing.T, id string) TEPVoucherID {
	t.Helper()

	v, err := NewTEPVoucherID(id)
	require.NoError(t, err)

	return v
}

func TestTEPSetTimeAndCerts(t *testing.T) {
	chain := [][]byte{{0x30, 1, 1}, {0x30, 2}}
	ocsp := [][]byte{{0xAA}, {0xBB, 0xBB}}

	var sent []byte

	cmd := &Command{Heci: tepMock(tepResponse(TEPCommandSetTimeCerts, TEPStatusSuccess, nil), &sent)}

	require.NoError(t, cmd.TEPSetTimeAndCerts(chain, ocsp))

	// The request is the full TEP_SET_TIME_CERTS_CMD struct: the MEI maximum of 12020 bytes.
	require.Len(t, sent, 12020)
	assert.Equal(t, []byte{CommandFeatureTEP, TEPCommandSetTimeCerts}, sent[:2])
	assert.Equal(t, uint16(12016), binary.LittleEndian.Uint16(sent[2:4]))

	body := sent[headerSize:]
	assert.Equal(t, []byte{3, 0, 2, 0, 0, 0, 0, 0}, body[:8], "certificate lengths")
	assert.Equal(t, []byte{0x30, 1, 1, 0x30, 2}, body[8:13])

	ocspOff := 8 + TEPCertChainBufferSize
	assert.Equal(t, []byte{1, 0, 2, 0, 0, 0, 0, 0}, body[ocspOff:ocspOff+8], "OCSP response lengths")
	assert.Equal(t, []byte{0xAA, 0xBB, 0xBB}, body[ocspOff+8:ocspOff+11])

	t.Run("maps TEP status", func(t *testing.T) {
		var sent []byte

		cmd := &Command{Heci: tepMock(tepResponse(TEPCommandSetTimeCerts, TEPStatusInvalidNonce, nil), &sent)}
		require.ErrorIs(t, cmd.TEPSetTimeAndCerts(chain, ocsp), ErrTEPInvalidNonce)
	})

	t.Run("rejects bad chains before sending", func(t *testing.T) {
		tooMany := [][]byte{{1}, {1}, {1}, {1}, {1}}
		tooBig := [][]byte{bytes.Repeat([]byte{1}, TEPCertChainBufferSize+1)}

		for name, tc := range map[string][2][][]byte{
			"empty chain":       {nil, ocsp},
			"empty OCSP":        {chain, nil},
			"five certificates": {tooMany, ocsp},
			"chain over 6000 B": {tooBig, ocsp},
			"empty certificate": {{{}}, ocsp},
		} {
			t.Run(name, func(t *testing.T) {
				m := &MockHECI{}
				require.ErrorIs(t, (&Command{Heci: m}).TEPSetTimeAndCerts(tc[0], tc[1]), ErrTEPInvalidChain)
			})
		}
	})

	t.Run("MEI client too small", func(t *testing.T) {
		m := &MockHECI{bufferSize: 4096}
		require.ErrorIs(t, (&Command{Heci: m}).TEPSetTimeAndCerts(chain, ocsp), ErrMessageTooLarge)
	})
}

func TestTEPRequestOwnershipVoucher(t *testing.T) {
	cms := []byte{0x30, 0x82, 0x01, 0x02, 0xAB}
	payload := binary.LittleEndian.AppendUint32(nil, uint32(len(cms)))
	payload = append(payload, cms...)
	payload = append(payload, make([]byte, TEPMaxJSONVoucherSize-len(cms))...)

	newRequest := func(t *testing.T) *TEPBinaryVoucherRequest {
		t.Helper()

		r := &TEPBinaryVoucherRequest{
			Version:        TEPVoucherVersion1,
			VoucherID:      mustVoucherID(t, "932586c2-d439-4154-86cb-49ba914aa716"),
			Assertion:      TEPAssertionVettedClaimed,
			OwnerID:        mustVoucherID(t, "9f8968c2-572d-4560-ae77-fabb77b78198"),
			CredentialType: TEPCredentialTypeDomainCA,
			HashAlgorithm:  TEPHashSHA384,
		}
		require.NoError(t, r.SetFeatures(TEPFeatureAMT))

		return r
	}

	for _, tc := range []struct {
		name    string
		prev    string
		command uint8
	}{
		{"new voucher", "", TEPCommandOwnershipVoucherRequest},
		{"nil previous voucher", nilUUID, TEPCommandOwnershipVoucherRequest},
		{"update", "11111111-2222-3333-4444-555555555555", TEPCommandOwnershipVoucherUpdateRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(t)
			copy(req.PrevVoucherID[:], tc.prev)

			var sent []byte

			cmd := &Command{Heci: tepMock(tepResponse(tc.command, TEPStatusSuccess, payload), &sent)}

			got, err := cmd.TEPRequestOwnershipVoucher(req)
			require.NoError(t, err)
			assert.Equal(t, cms, got)

			require.Len(t, sent, headerSize+564)
			assert.Equal(t, []byte{CommandFeatureTEP, tc.command, 0x34, 0x02}, sent[:headerSize], "ByteCount 564")
			assert.Equal(t, uint32(TEPVoucherFormatCMSJSON), binary.LittleEndian.Uint32(sent[headerSize:]), "format defaulted")
			assert.Equal(t, TEPVoucherFormat(0), req.Format, "caller's request is not modified")
		})
	}

	t.Run("length exceeds buffer", func(t *testing.T) {
		_, err := parseTEPVoucherCMS(binary.LittleEndian.AppendUint32(nil, 10))
		require.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("length exceeds maximum", func(t *testing.T) {
		oversized := binary.LittleEndian.AppendUint32(nil, TEPMaxJSONVoucherSize+1)
		oversized = append(oversized, make([]byte, TEPMaxJSONVoucherSize+1)...)

		_, err := parseTEPVoucherCMS(oversized)
		require.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("empty voucher request", func(t *testing.T) {
		_, err := parseTEPVoucherCMS(make([]byte, uint32Size+TEPMaxJSONVoucherSize))
		require.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("short payload", func(t *testing.T) {
		_, err := parseTEPVoucherCMS([]byte{1, 0})
		require.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := (&Command{Heci: &MockHECI{}}).TEPRequestOwnershipVoucher(nil)
		require.ErrorIs(t, err, ErrTEPEmptyVoucher)
	})

	t.Run("not allowed", func(t *testing.T) {
		var sent []byte

		cmd := &Command{Heci: tepMock(tepResponse(TEPCommandOwnershipVoucherRequest, TEPStatusNotAllowed, nil), &sent)}

		_, err := cmd.TEPRequestOwnershipVoucher(newRequest(t))
		require.ErrorIs(t, err, ErrTEPNotAllowed)
	})
}

func TestTEPBinaryVoucherRequestSetFeatures(t *testing.T) {
	var r TEPBinaryVoucherRequest

	require.NoError(t, r.SetFeatures(TEPFeatureAMT, TEPFeatureOEM1))
	assert.Equal(t, TEPOID{X: 5, Y: 101}, r.Features[0])
	assert.Equal(t, TEPOID{X: 5, Y: 150}, r.Features[1])
	assert.True(t, r.Features[2].IsZero())

	require.NoError(t, r.SetFeatures(TEPFeatureCapMgmt))
	assert.True(t, r.Features[1].IsZero(), "previous features are cleared")

	require.ErrorIs(t, r.SetFeatures(make([]TEPFeature, TEPMaxVoucherFeatures+1)...), ErrTEPTooManyFeatures)
}

func TestTEPSetOwnershipVoucher(t *testing.T) {
	id := mustVoucherID(t, "932586c2-d439-4154-86cb-49ba914aa716")
	cms := []byte{0x30, 0x03, 0x02, 0x01, 0x07}

	var sent []byte

	cmd := &Command{Heci: tepMock(tepResponse(TEPCommandSetOwnership, TEPStatusSuccess, nil), &sent)}

	require.NoError(t, cmd.TEPSetOwnershipVoucher(id, cms))

	require.Len(t, sent, headerSize+TEPVoucherIDSize+uint32Size+TEPMaxJSONVoucherSize)
	body := sent[headerSize:]
	assert.Equal(t, id[:], body[:TEPVoucherIDSize])
	assert.Equal(t, uint32(len(cms)), binary.LittleEndian.Uint32(body[TEPVoucherIDSize:]))
	assert.Equal(t, cms, body[TEPVoucherIDSize+uint32Size:TEPVoucherIDSize+uint32Size+len(cms)])

	t.Run("voucher mismatch", func(t *testing.T) {
		var sent []byte

		cmd := &Command{Heci: tepMock(tepResponse(TEPCommandSetOwnership, TEPStatusInvalidVoucher, nil), &sent)}
		require.ErrorIs(t, cmd.TEPSetOwnershipVoucher(id, cms), ErrTEPInvalidVoucher)
	})

	t.Run("too large", func(t *testing.T) {
		err := (&Command{Heci: &MockHECI{}}).TEPSetOwnershipVoucher(id, make([]byte, TEPMaxJSONVoucherSize+1))
		require.ErrorIs(t, err, ErrTEPVoucherTooLarge)
	})

	t.Run("empty", func(t *testing.T) {
		err := (&Command{Heci: &MockHECI{}}).TEPSetOwnershipVoucher(id, nil)
		require.ErrorIs(t, err, ErrTEPEmptyVoucher)
	})
}

func TestTEPRemoveOwnershipVoucher(t *testing.T) {
	id := mustVoucherID(t, "932586c2-d439-4154-86cb-49ba914aa716")

	var sent []byte

	cmd := &Command{Heci: tepMock(tepResponse(TEPCommandOwnershipRemove, TEPStatusSuccess, nil), &sent)}

	require.NoError(t, cmd.TEPRemoveOwnershipVoucher(id))
	assert.Equal(t, append([]byte{CommandFeatureTEP, TEPCommandOwnershipRemove, 36, 0}, id[:]...), sent)

	t.Run("active voucher", func(t *testing.T) {
		var sent []byte

		cmd := &Command{Heci: tepMock(tepResponse(TEPCommandOwnershipRemove, TEPStatusNotAllowed, nil), &sent)}
		require.ErrorIs(t, cmd.TEPRemoveOwnershipVoucher(id), ErrTEPNotAllowed)
	})
}
