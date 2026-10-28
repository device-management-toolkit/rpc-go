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

func fullChainResponse(status uint32, lengths []uint16, chain []byte) []byte {
	resp := []byte{CommandFeaturePlatformID, CommandOEMPlatformIDGetFullCertChain, 0, 0}
	resp = binary.LittleEndian.AppendUint32(resp, status)

	var lens [CSMESignatureMaxCerts]uint16
	copy(lens[:], lengths)

	for _, l := range lens {
		resp = binary.LittleEndian.AppendUint16(resp, l)
	}

	buf := make([]byte, TEPCertChainBufferSize)
	copy(buf, chain)

	return append(resp, buf...)
}

func TestGetFullCertificateChain(t *testing.T) {
	resp := fullChainResponse(uint32(StatusSuccess), []uint16{2, 3}, []byte{0x30, 0x00, 0x30, 0x01, 0xFF})

	var sent [][]byte

	m := &MockHECI{
		bufferSize: 16 * 1024,
		sendMessageFunc: func(buffer []byte, _ *uint32) (int, error) {
			sent = append(sent, append([]byte(nil), buffer...))

			return len(buffer), nil
		},
		receiveMessageFunc: func(buffer []byte, done *uint32) (int, error) {
			// Feature enable, chain, feature disable.
			r := resp
			if len(sent) != 2 {
				r = []byte{CommandFeaturePlatformID, CommandFeatureStateSet, 4, 0, 0, 0, 0, 0}
			}

			return respondWith(r)(buffer, done)
		},
	}

	chain, err := (&Command{Heci: m}).GetFullCertificateChain(CertIndexTEP)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{{0x30, 0x00}, {0x30, 0x01, 0xFF}}, chain)

	require.Len(t, sent, 3)
	assert.Equal(t, []byte{CommandFeaturePlatformID, CommandFeatureStateSet, 1, 0, 1}, sent[0], "enable UPID feature")
	assert.Equal(t, []byte{CommandFeaturePlatformID, CommandOEMPlatformIDGetFullCertChain, 4, 0, 2, 0, 0, 0}, sent[1], "cert_idx = TEP")
	assert.Equal(t, []byte{CommandFeaturePlatformID, CommandFeatureStateSet, 1, 0, 0}, sent[2], "disable UPID feature")
	assert.True(t, m.closed)

	t.Run("UPID status error", func(t *testing.T) {
		var sent []byte

		cmd := &Command{Heci: tepMock(fullChainResponse(uint32(StatusInvalidState), nil, nil), &sent)}

		_, err := cmd.GetFullCertificateChain(CertIndexOS)
		require.ErrorIs(t, err, ErrInvalidState)
	})

	t.Run("lengths overrun chain", func(t *testing.T) {
		_, err := parseFullCertChain(fullChainResponse(0, []uint16{TEPCertChainBufferSize, 1}, nil)[minResponseSize:])
		require.ErrorIs(t, err, ErrInvalidCertChain)
	})

	t.Run("short", func(t *testing.T) {
		_, err := parseFullCertChain([]byte{1, 0})
		require.ErrorIs(t, err, ErrInvalidResponse)
	})

	t.Run("no certificates", func(t *testing.T) {
		_, err := parseFullCertChain(fullChainResponse(0, nil, nil)[minResponseSize:])
		require.ErrorIs(t, err, ErrInvalidResponse)
	})
}
