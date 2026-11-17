/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package heci

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMEIGUIDFromString(t *testing.T) {
	tests := []struct {
		name string
		guid string
		want [16]byte
	}{
		{
			name: "PTHI matches MEI_IAMTHIF",
			guid: "{12F80028-B4B7-4B2D-ACA8-46E0FF65814C}",
			want: [16]byte{0x28, 0x00, 0xf8, 0x12, 0xb7, 0xb4, 0x2d, 0x4b, 0xac, 0xa8, 0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c},
		},
		{
			name: "LME matches MEI_LMEIF",
			guid: "{6733A4DB-0476-4E7B-B3AF-BCFC29BEE7A7}",
			want: [16]byte{0xdb, 0xa4, 0x33, 0x67, 0x76, 0x04, 0x7b, 0x4e, 0xb3, 0xaf, 0xbc, 0xfc, 0x29, 0xbe, 0xe7, 0xa7},
		},
		{
			name: "Watchdog matches MEI_WDIF",
			guid: "{05B79A6F-4628-4D7F-899D-A91514CB32AB}",
			want: [16]byte{0x6f, 0x9a, 0xb7, 0x05, 0x28, 0x46, 0x7f, 0x4d, 0x89, 0x9D, 0xA9, 0x15, 0x14, 0xCB, 0x32, 0xAB},
		},
		{
			name: "UPID without braces, lowercase",
			guid: "92136c79-5fea-4cfd-980e-23be07fa5e9f",
			want: [16]byte{0x79, 0x6c, 0x13, 0x92, 0xea, 0x5f, 0xfd, 0x4c, 0x98, 0x0e, 0x23, 0xbe, 0x07, 0xfa, 0x5e, 0x9f},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := meiGUIDFromString(tt.guid)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMEIGUIDFromStringInvalid(t *testing.T) {
	for _, guid := range []string{
		"",
		"{12F80028-B4B7-4B2D-ACA8}",
		"12F80028B4B74B2DACA846E0FF65814C",
		"{12F80028-B4B7-4B2D-ACA8-46E0FF65814G}",
		"{12F8002-B4B7-4B2D-ACA8-46E0FF65814C0}",
	} {
		_, err := meiGUIDFromString(guid)
		assert.Error(t, err, guid)
	}
}
