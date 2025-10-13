//go:build windows && amt
// +build windows,amt

/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

func TestInit(t *testing.T) {
	pthiguid, err := windows.GUIDFromString("{12F80028-B4B7-4B2D-ACA8-46E0FF65814C}")
	assert.NoError(t, err)
	lmeguid, err := windows.GUIDFromString("{6733A4DB-0476-4E7B-B3AF-BCFC29BEE7A7}")
	assert.NoError(t, err)
	wdguid, err := windows.GUIDFromString("{05B79A6F-4628-4D7F-899D-A91514CB32AB}")
	assert.NoError(t, err)

	tests := []struct {
		name             string
		useLME           bool
		useWD            bool
		expectClientGUID *windows.GUID
	}{
		{
			name:             "should use PTHI client for messaging",
			useLME:           false,
			useWD:            false,
			expectClientGUID: &pthiguid,
		},
		{
			name:             "should use LME client for messaging",
			useLME:           true,
			useWD:            false,
			expectClientGUID: &lmeguid,
		},
		{
			name:             "should use LME client for messaging",
			useLME:           true,
			useWD:            true,
			expectClientGUID: &lmeguid,
		},
		{
			name:             "should use Watchdog client for messaging",
			useLME:           false,
			useWD:            true,
			expectClientGUID: &wdguid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := Driver{}
			defer h.Close()
			_ = h.Init(tc.useLME, tc.useWD)
			assert.Equal(t, *tc.expectClientGUID, *h.clientGUID)
		})
	}
}

func TestFindDevices(t *testing.T) {
	h := Driver{}
	err := h.Init(false, false)
	assert.NoError(t, err)
}
