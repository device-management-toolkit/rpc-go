package local

import (
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhysicalIdentifiers(t *testing.T) {
	oldSerial, oldUPID := readSystemSerialNumber, readUPID

	t.Cleanup(func() { readSystemSerialNumber, readUPID = oldSerial, oldUPID })

	platformID, err := upid.NewUPID(make([]byte, upid.UPIDSize), upid.PlatformIDTypeNotSet)
	require.NoError(t, err)

	for _, tt := range []struct {
		name      string
		serial    string
		serialErr error
		id        *upid.UPID
		idErr     error
	}{
		{"both available", "PF4ABCDE", nil, platformID, nil},
		{"unsupported UPID", "PF4ABCDE", nil, nil, upid.ErrUPIDNotSupported},
		{"missing serial", "", utils.ErrSerialNumberUnavailable, platformID, nil},
		{"both unavailable", "", utils.ErrSerialNumberUnavailable, nil, upid.ErrUPIDNotSupported},
	} {
		t.Run(tt.name, func(t *testing.T) {
			readSystemSerialNumber = func() (string, error) { return tt.serial, tt.serialErr }
			readUPID = func() (*upid.UPID, error) { return tt.id, tt.idErr }
			f := flags.NewFlags(nil, MockPRSuccess)
			f.JsonOutput = true
			f.AmtInfo.SerialNumber, f.AmtInfo.UPID = true, true
			service := setupService(f)
			data := map[string]interface{}{"uuid": "existing-uuid"}
			service.addPhysicalIdentifiers(data)

			assert.Equal(t, "existing-uuid", data["uuid"])
			assert.Equal(t, tt.serial != "", data["serialNumber"] != nil)
			assert.Equal(t, tt.id != nil, data["upid"] != nil)
		})
	}
}

func TestPhysicalIdentifiersNotSelected(t *testing.T) {
	oldSerial, oldUPID := readSystemSerialNumber, readUPID

	t.Cleanup(func() { readSystemSerialNumber, readUPID = oldSerial, oldUPID })

	readSystemSerialNumber = func() (string, error) {
		t.Fatal("unexpected serial read")

		return "", nil
	}
	readUPID = func() (*upid.UPID, error) {
		t.Fatal("unexpected UPID read")

		return nil, nil
	}
	service := setupService(flags.NewFlags(nil, MockPRSuccess))
	data := map[string]interface{}{}

	service.addPhysicalIdentifiers(data)

	assert.Empty(t, data)
}
