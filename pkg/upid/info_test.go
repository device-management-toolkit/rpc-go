/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package upid

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUPIDInfoOEMNotProvisioned(t *testing.T) {
	raw := make([]byte, UPIDSize)
	for i := OEMPlatformIDSize; i < UPIDSize; i++ {
		raw[i] = 0xAB
	}

	u, err := NewUPID(raw, PlatformIDTypeNotSet)
	require.NoError(t, err)

	info := u.Info()
	require.NotNil(t, info)
	assert.Equal(t, strings.Repeat("AB", HWSerialNumSize), info.CSMEId)
	assert.Equal(t, strings.Repeat("00", OEMPlatformIDSize), info.OEMId, "unprovisioned OEM ID is reported as zeros, matching v3 amtinfo --sync")
	assert.Equal(t, "Not Set (0)", info.OEMPlatformIdType)

	encoded, err := json.Marshal(info)
	require.NoError(t, err)
	assert.JSONEq(t, `{"csmeId":"`+strings.Repeat("AB", HWSerialNumSize)+`","oemId":"`+strings.Repeat("00", OEMPlatformIDSize)+`","oemPlatformIdType":"Not Set (0)"}`, string(encoded))
}

func TestFormatHex(t *testing.T) {
	assert.Equal(t, "", formatHex(nil))
	assert.Equal(t, "0AFF", formatHex([]byte{0x0A, 0xFF}))
}

func TestUPIDInfoOEMProvisioned(t *testing.T) {
	raw := make([]byte, UPIDSize)
	raw[0] = 0x01
	raw[UPIDSize-1] = 0xFF

	u, err := NewUPID(raw, PlatformIDTypeBinary)
	require.NoError(t, err)

	info := u.Info()
	assert.Equal(t, "01"+strings.Repeat("00", OEMPlatformIDSize-1), info.OEMId)
	assert.Equal(t, strings.Repeat("00", HWSerialNumSize-1)+"FF", info.CSMEId)
	assert.Equal(t, "Binary (1)", info.OEMPlatformIdType)
}

func TestUPIDInfoNil(t *testing.T) {
	var u *UPID

	assert.Nil(t, u.Info())
}

func TestPlatformIDTypeString(t *testing.T) {
	assert.Equal(t, "Not Set (0)", platformIDTypeString(PlatformIDTypeNotSet))
	assert.Equal(t, "Binary (1)", platformIDTypeString(PlatformIDTypeBinary))
	assert.Equal(t, "Printable String (2)", platformIDTypeString(PlatformIDTypePrintableString))
	assert.Equal(t, "Unknown (7)", platformIDTypeString(7))
}
