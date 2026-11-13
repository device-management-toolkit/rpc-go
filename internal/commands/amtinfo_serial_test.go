package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestAmtInfoSerialNumber(t *testing.T) {
	original := getSystemSerialNumber

	t.Cleanup(func() { getSystemSerialNumber = original })

	for _, tt := range []struct {
		name   string
		serial string
		err    error
	}{
		{"available", "PF4ABCDE", nil},
		{"unavailable", "", utils.ErrSerialNumberUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			getSystemSerialNumber = func() (string, error) { return tt.serial, tt.err }
			service := NewInfoService(nil, WithHECIAvailable(false))
			result, _ := service.collectAMTInfo(&AmtInfoCmd{SerialNumber: true, Hostname: true}, false)
			assert.Equal(t, tt.serial, result.SerialNumber)
			assert.NotEmpty(t, result.HostnameOS)
			data, err := json.Marshal(result)
			require.NoError(t, err)

			if tt.serial == "" {
				assert.NotContains(t, string(data), "serialNumber")
			} else {
				assert.Contains(t, string(data), `"serialNumber":"PF4ABCDE"`)
			}
		})
	}
}

func TestAmtInfoSerialNumberSelection(t *testing.T) {
	original := getSystemSerialNumber

	t.Cleanup(func() { getSystemSerialNumber = original })

	called := false
	getSystemSerialNumber = func() (string, error) {
		called = true

		return "serial", nil
	}
	cmd := &AmtInfoCmd{Hostname: true}
	service := NewInfoService(nil, WithHECIAvailable(false))
	result, _ := service.collectAMTInfo(cmd, false)

	assert.False(t, called)
	assert.Empty(t, result.SerialNumber)
	assert.False(t, (&AmtInfoCmd{SerialNumber: true}).HasNoFlagsSet())
}

func TestAmtInfoUnavailableIdentifiers(t *testing.T) {
	original := getSystemSerialNumber

	t.Cleanup(func() { getSystemSerialNumber = original })

	getSystemSerialNumber = func() (string, error) { return "", utils.ErrSerialNumberUnavailable }

	errRead := errors.New("read failed")

	for _, tt := range []struct {
		name       string
		upidErr    error
		wantStatus string
	}{
		{"UPID not supported", fmt.Errorf("%w: handle is invalid", upid.ErrUPIDNotSupported), "Not Supported"},
		{"UPID read failure", errRead, "Not Available (read failed)"},
		{"UPID empty", nil, "Not Available"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAMT := mock.NewMockInterface(ctrl)
			mockAMT.EXPECT().GetUPID().Return(nil, tt.upidErr)

			cmd := &AmtInfoCmd{SerialNumber: true, UPID: true}
			service := NewInfoService(mockAMT, WithHECIAvailable(false))
			result, _ := service.collectAMTInfo(cmd, false)

			require.Nil(t, result.UPID)
			assert.Equal(t, tt.wantStatus, result.upidStatus)
			assert.True(t, result.serialUnavailable)

			// JSON output is unchanged: unavailable identifiers are omitted.
			data, err := json.Marshal(result)
			require.NoError(t, err)
			assert.NotContains(t, string(data), "upid")
			assert.NotContains(t, string(data), "serialNumber")

			var table bytes.Buffer

			require.NoError(t, service.OutputTable(&table, result, cmd))
			assert.Contains(t, table.String(), tt.wantStatus)
			assert.Contains(t, table.String(), "Serial Number")

			upidSection := buildUPIDSection(result, cmd, false)
			assert.Contains(t, upidSection, "Intel UPID")
			assert.Contains(t, upidSection, tt.wantStatus)

			deviceSection := buildDeviceSection(result, cmd, false, false)
			assert.Contains(t, deviceSection, "Serial Number")
			assert.Contains(t, deviceSection, "Not Available")
		})
	}
}

func TestAmtInfoIdentifiersNotRequested(t *testing.T) {
	cmd := &AmtInfoCmd{Hostname: true}
	service := NewInfoService(nil, WithHECIAvailable(false))
	result, _ := service.collectAMTInfo(cmd, false)

	assert.Empty(t, result.upidStatus)
	assert.False(t, result.serialUnavailable)
	assert.Empty(t, buildUPIDSection(result, cmd, false))
	assert.NotContains(t, buildDeviceSection(result, cmd, false, false), "Serial Number")
}
