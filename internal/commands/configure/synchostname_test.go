/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
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
	mockWSMAN.EXPECT().GetGeneralSettings().Return(general.Response{}, nil)
	mockWSMAN.EXPECT().PutGeneralSettings(gomock.Any()).Return(general.Response{}, nil)

	err := cmd.Run(ctx)
	assert.NoError(t, err)
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
