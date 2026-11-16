/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// stubSerialNumber replaces the serial number source for the test.
func stubSerialNumber(t *testing.T, serial string, err error) *int {
	t.Helper()

	original := getSystemSerialNumber

	t.Cleanup(func() { getSystemSerialNumber = original })

	calls := 0
	getSystemSerialNumber = func() (string, error) {
		calls++

		return serial, err
	}

	return &calls
}

func TestAmtInfoSerialNumber(t *testing.T) {
	for _, tt := range []struct {
		name       string
		serial     string
		err        error
		wantReason string
	}{
		{name: "available", serial: "PF4ABCDE"},
		{name: "not set by the OEM", err: utils.ErrSerialNumberUnavailable, wantReason: "not set by the OEM"},
		{name: "needs root", err: fs.ErrPermission, wantReason: "requires elevated privileges"},
		{name: "read failure", err: errors.New("powershell missing"), wantReason: "could not be read"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stubSerialNumber(t, tt.serial, tt.err)

			cmd := &AmtInfoCmd{SerialNumber: true, Hostname: true}
			service := NewInfoService(nil, WithHECIAvailable(false))
			result, _ := service.collectAMTInfo(cmd, false)

			assert.Equal(t, tt.serial, result.SerialNumber)
			assert.Equal(t, tt.wantReason, result.serialUnavailable)
			assert.NotEmpty(t, result.HostnameOS, "an unreadable serial number must not stop other fields")

			// JSON reports the value or omits the key.
			data, err := json.Marshal(result)
			require.NoError(t, err)

			var keys map[string]json.RawMessage

			require.NoError(t, json.Unmarshal(data, &keys))

			var table bytes.Buffer

			require.NoError(t, service.OutputTable(&table, result, cmd))

			section := buildDeviceSection(result, cmd, false, false)

			if tt.serial != "" {
				assert.JSONEq(t, `"PF4ABCDE"`, string(keys["serialNumber"]))
				assert.Contains(t, table.String(), "PF4ABCDE")
				assert.Contains(t, section, "PF4ABCDE")

				return
			}

			want := "Unavailable (" + tt.wantReason + ")"

			assert.NotContains(t, keys, "serialNumber")
			assert.Contains(t, table.String(), "Serial Number")
			assert.Contains(t, table.String(), want)
			assert.Contains(t, section, "Serial Number")
			assert.Contains(t, section, want)
		})
	}
}

func TestAmtInfoSerialNumberSelection(t *testing.T) {
	t.Run("not read when another field is selected", func(t *testing.T) {
		calls := stubSerialNumber(t, "PF4ABCDE", nil)

		cmd := &AmtInfoCmd{Hostname: true}
		service := NewInfoService(nil, WithHECIAvailable(false))
		result, _ := service.collectAMTInfo(cmd, false)

		assert.Zero(t, *calls)
		assert.Empty(t, result.SerialNumber)
		assert.Empty(t, result.serialUnavailable)
		assert.NotContains(t, buildDeviceSection(result, cmd, false, false), "Serial Number")
	})

	t.Run("selecting it is not the default output", func(t *testing.T) {
		assert.False(t, (&AmtInfoCmd{SerialNumber: true}).HasNoFlagsSet())
	})

	for name, cmd := range map[string]*AmtInfoCmd{
		"read by default": {},
		"read with --all": {All: true},
	} {
		t.Run(name, func(t *testing.T) {
			calls := stubSerialNumber(t, "PF4ABCDE", nil)

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAMT := mock.NewMockInterface(ctrl)
			mockAMT.EXPECT().GetUPID().Return(nil, nil).AnyTimes()
			mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil).AnyTimes()

			service := NewInfoService(mockAMT, WithHECIAvailable(false))
			result, _ := service.collectAMTInfo(cmd, false)

			assert.Equal(t, 1, *calls)
			assert.Equal(t, "PF4ABCDE", result.SerialNumber)

			var table bytes.Buffer

			require.NoError(t, service.OutputTable(&table, result, cmd))
			assert.Contains(t, table.String(), "PF4ABCDE")
			assert.Contains(t, buildDeviceSection(result, cmd, true, false), "PF4ABCDE")
		})
	}
}
