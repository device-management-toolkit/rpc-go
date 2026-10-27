/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package pthi

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func provisioningLogMessage(t *testing.T, status Status, length uint32, log ProvisioningLog) []byte {
	t.Helper()

	resp := GetProvisioningLogResponse{
		Header: ResponseMessageHeader{
			Header: MessageHeader{Command: CommandFormat{Val: GET_HBP_PROV_LOG_RESPONSE}, Length: length},
			Status: status,
		},
		ProvisioningLog: log,
	}

	var buf bytes.Buffer

	require.NoError(t, binary.Write(&buf, binary.LittleEndian, resp))

	return buf.Bytes()
}

func TestGetProvisioningLog(t *testing.T) {
	numBytes = GET_REQUEST_SIZE + 1 // header plus the version byte

	want := ProvisioningLog{
		CcmProvisioningStatus: PROV_RES_INVALID,
		AcmProvisioningStatus: PROV_RES_TEP_OWNERSHIP_EXPIRED,
		AcmStartingTime:       1_700_000_000,
		AcmCompletionTime:     1_700_000_005,
	}

	t.Run("success", func(t *testing.T) {
		message = provisioningLogMessage(t, AMT_STATUS_SUCCESS, 25, want)

		got, err := pthi.GetProvisioningLog()
		require.NoError(t, err)
		assert.Equal(t, want, got.ProvisioningLog)
		assert.True(t, got.ProvisioningLog.AcmProvisioningStatus.IsTEP())
		assert.Equal(t, "Expired TEP ownership", got.ProvisioningLog.AcmProvisioningStatus.String())
	})

	t.Run("firmware status failure", func(t *testing.T) {
		message = provisioningLogMessage(t, AMT_STATUS_INTERNAL_ERROR, 25, want)

		_, err := pthi.GetProvisioningLog()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AMT_STATUS_INTERNAL_ERROR")
	})

	t.Run("declared length too short", func(t *testing.T) {
		message = provisioningLogMessage(t, AMT_STATUS_SUCCESS, 5, want)

		_, err := pthi.GetProvisioningLog()
		require.ErrorIs(t, err, ErrProvisioningLogTruncated)
	})

	t.Run("received fewer bytes than declared", func(t *testing.T) {
		// Header still declares the full 25 bytes, but the log is cut off
		// after the version and 3 log bytes.
		message = provisioningLogMessage(t, AMT_STATUS_SUCCESS, 25, want)[:provisioningLogHeaderSize+4]

		_, err := pthi.GetProvisioningLog()
		require.ErrorIs(t, err, ErrProvisioningLogTruncated)
	})

	t.Run("header cut off", func(t *testing.T) {
		message = provisioningLogMessage(t, AMT_STATUS_SUCCESS, 25, want)[:provisioningLogHeaderSize-1]

		_, err := pthi.GetProvisioningLog()
		require.ErrorIs(t, err, ErrProvisioningLogTruncated)
	})

	t.Run("failure status without a log", func(t *testing.T) {
		message = provisioningLogMessage(t, AMT_STATUS_INTERNAL_ERROR, 4, ProvisioningLog{})[:provisioningLogHeaderSize]

		_, err := pthi.GetProvisioningLog()
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrProvisioningLogTruncated)
		assert.Contains(t, err.Error(), "AMT_STATUS_INTERNAL_ERROR")
	})
}

func TestProvisioningAttemptResult(t *testing.T) {
	assert.Equal(t, "Success", PROV_RES_SUCCESS.String())
	assert.Equal(t, "Unknown provisioning result (42)", ProvisioningAttemptResult(42).String())
	assert.False(t, PROV_RES_UNTRUSTED_ROOT.IsTEP())
	assert.True(t, PROV_RES_TEP_HASH_MISMATCH.IsTEP())
	assert.True(t, PROV_RES_TEP_MISSING_CA_OID.IsTEP())
	assert.False(t, ProvisioningAttemptResult(12).IsTEP())
}
