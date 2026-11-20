/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"os"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestSyncHostnameCmd_Run_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	cmd := &SyncHostnameCmd{
		ConfigureBaseCmd: ConfigureBaseCmd{
			AMTBaseCmd: commands.AMTBaseCmd{
				ControlMode: 1,
				WSMan:       mockWSMAN,
			},
		},
	}

	ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

	// Mock dependencies
	mockAMT.EXPECT().GetOSDNSSuffix().Return("example.com", nil)

	current := general.Response{}
	current.Body.GetResponse = general.GeneralSettingsResponse{
		ElementName:                   "Intel(r) AMT: General Settings",
		InstanceID:                    "Intel(r) AMT: General Settings",
		IdleWakeTimeout:               15,
		HostName:                      "old-host",
		DomainName:                    "old.example",
		PingResponseEnabled:           true,
		DDNSUpdateByDHCPServerEnabled: true,
		SharedFQDN:                    true,
		HostOSFQDN:                    "old-host",
		AMTNetworkEnabled:             1,
		RmcpPingResponseEnabled:       true,
		DHCPSyncRequiresHostname:      1,
	}
	mockWSMAN.EXPECT().GetGeneralSettings().Return(current, nil)

	var sent general.GeneralSettingsRequest

	mockWSMAN.EXPECT().PutGeneralSettings(gomock.Any()).DoAndReturn(func(req general.GeneralSettingsRequest) (general.Response, error) {
		sent = req

		return general.Response{}, nil
	})

	err := cmd.Run(ctx)
	assert.NoError(t, err)

	hostname, _ := os.Hostname()
	assert.Equal(t, hostname, sent.HostName)
	assert.Equal(t, "example.com", sent.DomainName)
	assert.Equal(t, "Intel(r) AMT: General Settings", sent.InstanceID)
	assert.Equal(t, "Intel(r) AMT: General Settings", sent.ElementName)
	assert.Equal(t, 15, sent.IdleWakeTimeout)
	assert.True(t, sent.PingResponseEnabled)
	assert.True(t, sent.DDNSUpdateByDHCPServerEnabled)
	assert.True(t, sent.SharedFQDN)
	assert.True(t, sent.RmcpPingResponseEnabled)
	assert.Equal(t, "old-host", sent.HostOSFQDN)
	assert.Equal(t, 1, sent.DHCPSyncRequiresHostname)
}

func TestSyncHostnameCmd_Run_KeepsDomainWhenOSHasNone(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	cmd := &SyncHostnameCmd{
		ConfigureBaseCmd: ConfigureBaseCmd{
			AMTBaseCmd: commands.AMTBaseCmd{
				ControlMode: 1,
				WSMan:       mockWSMAN,
			},
		},
	}

	ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

	mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil)

	current := general.Response{}
	current.Body.GetResponse = general.GeneralSettingsResponse{DomainName: "old.example"}
	mockWSMAN.EXPECT().GetGeneralSettings().Return(current, nil)

	var sent general.GeneralSettingsRequest

	mockWSMAN.EXPECT().PutGeneralSettings(gomock.Any()).DoAndReturn(func(req general.GeneralSettingsRequest) (general.Response, error) {
		sent = req

		return general.Response{}, nil
	})

	assert.NoError(t, cmd.Run(ctx))
	assert.Equal(t, "old.example", sent.DomainName)
}

func TestSyncHostnameCmd_Run_NotActivated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)

	cmd := &SyncHostnameCmd{
		ConfigureBaseCmd: ConfigureBaseCmd{
			AMTBaseCmd: commands.AMTBaseCmd{
				ControlMode: 0,
			},
		},
	}

	ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

	err := cmd.Run(ctx)
	assert.Error(t, err)
}

func TestSyncHostnameCmd_Run_GetGeneralSettingsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	cmd := &SyncHostnameCmd{
		ConfigureBaseCmd: ConfigureBaseCmd{
			AMTBaseCmd: commands.AMTBaseCmd{
				ControlMode: 1,
				WSMan:       mockWSMAN,
			},
		},
	}

	ctx := &commands.Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

	mockAMT.EXPECT().GetOSDNSSuffix().Return("example.com", nil)
	mockWSMAN.EXPECT().GetGeneralSettings().Return(general.Response{}, errors.New("boom"))

	err := cmd.Run(ctx)
	assert.Error(t, err)
}
