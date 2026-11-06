package commands

import (
	"encoding/json"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
