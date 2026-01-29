/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package amt

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

type MockPTHICommands struct{}

func (c MockPTHICommands) OpenWatchdog() error {
	if flag == true {
		return errors.New("the handle is invalid")
	} else if flag1 == true {
		return errors.New("")
	} else {
		return nil
	}
}

var (
	flag        bool = false
	flag1       bool = false
	returnError bool = false
)

func (c MockPTHICommands) Open(useLME bool) error {
	if flag == true {
		return errors.New("The handle is invalid.")
	} else if flag1 == true {
		return errors.New("")
	} else {
		return nil
	}
}
func (c MockPTHICommands) Close() {}
func (c MockPTHICommands) Call(command []byte, commandSize int) (result []byte, err error) {
	return nil, nil
}

func (c MockPTHICommands) GetCodeVersions() (pthi.GetCodeVersionsResponse, error) {
	if returnError == true {
		return pthi.GetCodeVersionsResponse{
			CodeVersion: pthi.CodeVersions{
				BiosVersion:   [65]uint8{84, 101, 115, 116},
				VersionsCount: 1,
				Versions: [50]pthi.AMTVersionType{{
					Description: pthi.AMTUnicodeString{
						Length: 5,
						String: [20]uint8{70, 108, 97, 115, 104},
					},
					Version: pthi.AMTUnicodeString{
						Length: 7,
						String: [20]uint8{49, 49, 46, 56, 46, 53, 53},
					},
				}},
			},
		}, errors.New("amt internal error")
	} else {
		return pthi.GetCodeVersionsResponse{
			CodeVersion: pthi.CodeVersions{
				BiosVersion:   [65]uint8{84, 101, 115, 116},
				VersionsCount: 1,
				Versions: [50]pthi.AMTVersionType{{
					Description: pthi.AMTUnicodeString{
						Length: 5,
						String: [20]uint8{70, 108, 97, 115, 104},
					},
					Version: pthi.AMTUnicodeString{
						Length: 7,
						String: [20]uint8{49, 49, 46, 56, 46, 53, 53},
					},
				}},
			},
		}, nil
	}
}

func (c MockPTHICommands) GetUUID() (uuid string, err error) {
	return "\xd2?\x11\x1c%3\x94E\xa2rT\xb2\x03\x8b\xeb\a", nil
}

func (c MockPTHICommands) GetIsAMTEnabled() (state uint8, err error) {
	return uint8(0x83), nil
}

var (
	SetOperationsStateStatus       = pthi.Status(0)
	SetOperationsStateError  error = nil
)

func (c MockPTHICommands) SetAmtOperationalState(state pthi.AMTOperationalState) (pthi.Status, error) {
	return SetOperationsStateStatus, SetOperationsStateError
}

func (c MockPTHICommands) GetControlMode() (state int, err error)       { return 0, nil }
func (c MockPTHICommands) GetProvisioningState() (state int, err error) { return 0, nil }
func (c MockPTHICommands) GetDNSSuffix() (suffix string, err error)     { return "Test", nil }
func (c MockPTHICommands) GetCertificateHashes(hashHandles pthi.AMTHashHandles) (hashEntryList []pthi.CertHashEntry, err error) {
	return []pthi.CertHashEntry{{
		CertificateHash: [64]uint8{84, 101, 115, 116},
		Name:            pthi.AMTANSIString{Length: 4, Buffer: [1000]uint8{84, 101, 115, 116}},
		HashAlgorithm:   2,
		IsActive:        1,
		IsDefault:       1,
	}}, nil
}

func (c MockPTHICommands) GetRemoteAccessConnectionStatus() (RAStatus pthi.GetRemoteAccessConnectionStatusResponse, err error) {
	return pthi.GetRemoteAccessConnectionStatusResponse{
		NetworkStatus: 2,
		RemoteStatus:  0,
		RemoteTrigger: 0,
		MPSHostname:   pthi.AMTANSIString{Length: 4, Buffer: [1000]uint8{84, 101, 115, 116}},
	}, nil
}

func (c MockPTHICommands) GetLANInterfaceSettings(useWireless bool) (LANInterface pthi.GetLANInterfaceSettingsResponse, err error) {
	if useWireless {
		return pthi.GetLANInterfaceSettingsResponse{
			Enabled:     0,
			Ipv4Address: 0,
			DhcpEnabled: 1,
			DhcpIpMode:  0,
			LinkStatus:  0,
			MacAddress:  [6]uint8{0, 0, 0, 0, 0, 0},
		}, nil
	} else {
		return pthi.GetLANInterfaceSettingsResponse{
			Enabled:     1,
			Ipv4Address: 0,
			DhcpEnabled: 1,
			DhcpIpMode:  2,
			LinkStatus:  1,
			MacAddress:  [6]uint8{7, 7, 7, 7, 7, 7},
		}, nil
	}
}

func (c MockPTHICommands) GetLocalSystemAccount() (localAccount pthi.GetLocalSystemAccountResponse, err error) {
	return pthi.GetLocalSystemAccountResponse{
		Account: pthi.LocalSystemAccount{
			Username: [33]uint8{84, 101, 115, 116},
			Password: [33]uint8{84, 101, 115, 116},
		},
	}, nil
}
func (c MockPTHICommands) Unprovision() (state int, err error) { return 0, nil }

func (c MockPTHICommands) StartConfigurationHBased(serverHashAlgorithm uint8, serverCertHash [64]byte, hostVPNEnable bool, suffixListLen int32, networkDNSSuffixList [320]byte) (response pthi.StartConfigurationHBasedResponse, err error) {
	return pthi.StartConfigurationHBasedResponse{}, nil
}

func (c MockPTHICommands) StopConfiguration() (response pthi.StopConfigurationResponse, err error) {
	return pthi.StopConfigurationResponse{}, nil
}

// MockHOTHAMCommands mocks HOTHAM interface for testing
type MockHOTHAMCommands struct{}

func (c MockHOTHAMCommands) Open() error {
	if flag {
		return errors.New("The handle is invalid.")
	}

	return nil
}

func (c MockHOTHAMCommands) Close() {}

func (c MockHOTHAMCommands) Call(command []byte, commandSize int) (result []byte, err error) {
	return nil, nil
}

func (c MockHOTHAMCommands) GetFlogSize() (size uint32, err error) {
	return 12, nil
}

func (c MockHOTHAMCommands) GetFlog() ([]byte, error) {
	// Return mock FLOG data for testing
	mockFlogData := []byte{
		0x46, 0x4C, 0x4F, 0x47, // "FLOG" magic
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}

	return mockFlogData, nil
}

var amt AMTCommand

func init() {
	amt = AMTCommand{}
	amt.PTHI = MockPTHICommands{}
	amt.HOTHAM = MockHOTHAMCommands{}
}

func TestInitializeNoError(t *testing.T) {
	err := amt.Initialize()
	assert.NoError(t, err)
}

func TestInitializeMEIError(t *testing.T) {
	flag = true
	err := amt.Initialize()
	assert.Error(t, err, utils.HECIDriverNotDetected)

	flag = false
}

func TestInitializeError(t *testing.T) {
	flag1 = true
	err := amt.Initialize()
	assert.Error(t, err, utils.HECIDriverNotDetected)

	flag1 = false
}

func TestGetVersionDataFromME(t *testing.T) {
	result, err := amt.GetVersionDataFromME("Flash", 1*time.Second)
	assert.NoError(t, err)
	assert.Equal(t, "11.8.55", result)
}

func TestGetVersionDataFromMEError(t *testing.T) {
	result, err := amt.GetVersionDataFromME("", 1*time.Second)
	assert.Error(t, err)
	assert.Equal(t, "", result)
}

// func TestGetVersionDataFromMETimeout1sec(t *testing.T) {
// 	returnError = true
// 	result, err := amt.GetVersionDataFromME("", 1*time.Second)
// 	assert.Equal(t, "amt internal error", err.Error())
// 	assert.Equal(t, "", result)
// }

//	func TestGetVersionDataFromMETimeout16sec(t *testing.T) {
//		returnError = true
//		result, err := amt.GetVersionDataFromME("", 16*time.Second)
//		assert.Equal(t, "amt internal error", err.Error())
//		assert.Equal(t, "", result)
//	}
func TestGetIsAMTEnabled(t *testing.T) {
	result, err := amt.GetChangeEnabled()
	assert.NoError(t, err)
	assert.True(t, result.IsAMTEnabled())
}

func TestGetIsAMTEnabledError(t *testing.T) {
	flag1 = true
	result, err := amt.GetChangeEnabled()
	assert.Error(t, err)
	assert.False(t, result.IsAMTEnabled())

	flag1 = false
}

func TestAmtOperationalState(t *testing.T) {
	t.Run("DisableAMT happy path", func(t *testing.T) {
		err := amt.DisableAMT()
		assert.NoError(t, err)
	})
	t.Run("EnableAMT happy path", func(t *testing.T) {
		err := amt.EnableAMT()
		assert.NoError(t, err)
	})
	t.Run("setAmtOperationalState expect error on open", func(t *testing.T) {
		flag1 = true
		err := amt.EnableAMT()
		assert.Error(t, err)

		flag1 = false
	})
	t.Run("setAmtOperationalState expect error setting op state", func(t *testing.T) {
		SetOperationsStateError = errors.New("test error")
		err := amt.EnableAMT()
		assert.Error(t, err)

		SetOperationsStateError = nil
	})
	t.Run("setAmtOperationalState expect error on bad return status", func(t *testing.T) {
		SetOperationsStateStatus = pthi.Status(5)
		err := amt.EnableAMT()
		assert.Error(t, err)

		SetOperationsStateStatus = pthi.Status(0)
	})
}

func TestEnableAMT(t *testing.T) {
	err := amt.EnableAMT()
	assert.NoError(t, err)
}

func TestGetGUID(t *testing.T) {
	result, err := amt.GetUUID()
	assert.NoError(t, err)
	assert.Equal(t, "1c113fd2-3325-4594-a272-54b2038beb07", result)
}

func TestGetControlmode(t *testing.T) {
	result, err := amt.GetControlMode()
	assert.NoError(t, err)
	assert.Equal(t, 0, result)
}

func TestGetDNSSuffix(t *testing.T) {
	result, err := amt.GetDNSSuffix()
	assert.NoError(t, err)
	assert.Equal(t, "Test", result)
}

func TestGetCertificateHashes(t *testing.T) {
	result, err := amt.GetCertificateHashes()
	assert.NoError(t, err)
	assert.Equal(t, "5465737400000000000000000000000000000000000000000000000000000000", result[0].Hash)
	assert.Equal(t, "Test", result[0].Name)
	assert.Equal(t, "SHA256", result[0].Algorithm)
	assert.Equal(t, true, result[0].IsActive)
	assert.Equal(t, true, result[0].IsDefault)
}

func TestGetRemoteAccessConnectionStatus(t *testing.T) {
	result, err := amt.GetRemoteAccessConnectionStatus()
	assert.NoError(t, err)
	assert.Equal(t, "outside enterprise", result.NetworkStatus)
	assert.Equal(t, "not connected", result.RemoteStatus)
	assert.Equal(t, "user initiated", result.RemoteTrigger)
	assert.Equal(t, "Test", result.MPSHostname)
}

func TestGetLANInterfaceSettingsTrue(t *testing.T) {
	result, err := amt.GetLANInterfaceSettings(true)
	assert.NoError(t, err)
	assert.NoError(t, err)
	assert.Equal(t, false, result.IsEnabled)
	assert.Equal(t, "down", result.LinkStatus)
	assert.Equal(t, "passive", result.DHCPMode)
	assert.Equal(t, "0.0.0.0", result.IPAddress)
	assert.Equal(t, "00:00:00:00:00:00", result.MACAddress)
}

func TestGetLANInterfaceSettingsFalse(t *testing.T) {
	result, err := amt.GetLANInterfaceSettings(false)
	assert.NoError(t, err)
	assert.Equal(t, true, result.IsEnabled)
	assert.Equal(t, "up", result.LinkStatus)
	assert.Equal(t, "passive", result.DHCPMode)
	assert.Equal(t, "0.0.0.0", result.IPAddress)
	assert.Equal(t, "07:07:07:07:07:07", result.MACAddress)
}

func TestGetLocalSystemAccount(t *testing.T) {
	result, err := amt.GetLocalSystemAccount()
	assert.NoError(t, err)
	assert.Equal(t, "Test", result.Username)
	assert.Equal(t, "Test", result.Password)
}

func TestUnprovision(t *testing.T) {
	result, err := amt.Unprovision()
	assert.NoError(t, err)
	assert.Equal(t, 0, result)
}

func TestChangeEnabledResponse(t *testing.T) {
	tests := []struct {
		value              uint8
		expectNewInterface bool
		expectEnabled      bool
		expectTransition   bool
	}{
		{
			value:              0x83,
			expectNewInterface: true,
			expectEnabled:      true,
			expectTransition:   true,
		},
		{
			value:              0x82,
			expectNewInterface: true,
			expectEnabled:      true,
			expectTransition:   false,
		},
		{
			value:              0x80,
			expectNewInterface: true,
			expectEnabled:      false,
			expectTransition:   false,
		},
		{
			value:              0x02,
			expectNewInterface: false,
			expectEnabled:      true,
			expectTransition:   false,
		},
		{
			value:              0x00,
			expectNewInterface: false,
			expectEnabled:      false,
			expectTransition:   false,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("response value: %#x", tt.value), func(t *testing.T) {
			cer := ChangeEnabledResponse(tt.value)
			assert.Equal(t, tt.expectNewInterface, cer.IsNewInterfaceVersion())
			assert.Equal(t, tt.expectEnabled, cer.IsAMTEnabled())
			assert.Equal(t, tt.expectTransition, cer.IsTransitionAllowed())
		})
	}
}

func TestGetFlog(t *testing.T) {
	result, err := amt.GetFlog()
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, len(result), 0)
	// Verify it contains the expected mock data
	assert.Equal(t, byte(0x46), result[0]) // 'F'
	assert.Equal(t, byte(0x4C), result[1]) // 'L'
	assert.Equal(t, byte(0x4F), result[2]) // 'O'
	assert.Equal(t, byte(0x47), result[3]) // 'G'
}
