/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestEnableAMTCmd_Run_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x81), nil) // 10000001 in binary
	mockAMT.EXPECT().EnableAMT().Return(nil)

	cmd := &EnableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestEnableAMTCmd_Run_AlreadyEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x83), nil) // 10000011 in binary

	cmd := &EnableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestEnableAMTCmd_Run_OldInterfaceVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x01), nil) // 00000001 in binary

	cmd := &EnableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AMT version does not support SetAmtOperationalState")
}

func TestEnableAMTCmd_Run_TransitionNotAllowed_ButSucceeds(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x80), nil) // 10000000 in binary - transition not allowed
	mockAMT.EXPECT().EnableAMT().Return(nil)                                         // But EnableAMT succeeds anyway

	cmd := &EnableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.NoError(t, err) // Should succeed despite transition not allowed flag
}

func TestEnableAMTCmd_Run_TransitionNotAllowed_AndFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x80), nil) // 10000000 in binary
	mockAMT.EXPECT().EnableAMT().Return(errors.New("AMT_STATUS_NOT_PERMITTED"))

	cmd := &EnableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to enable AMT")
}

func TestEnableAMTCmd_Run_EnableAMTError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x81), nil) // 10000001 in binary
	mockAMT.EXPECT().EnableAMT().Return(errors.New("enable failed"))

	cmd := &EnableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to enable AMT")
}

func TestEnableAMTCmd_Run_GetChangeEnabledError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), errors.New("connection failed"))

	cmd := &EnableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.Error(t, err)
}
