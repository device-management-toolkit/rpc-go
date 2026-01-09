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

func TestDisableAMTCmd_Run_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x83), nil) // 10000011 in binary
	mockAMT.EXPECT().DisableAMT().Return(nil)

	cmd := &DisableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestDisableAMTCmd_Run_AlreadyDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x81), nil) // 10000001 in binary

	cmd := &DisableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.NoError(t, err)
}

func TestDisableAMTCmd_Run_OldInterfaceVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x03), nil) // 00000011 in binary

	cmd := &DisableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AMT version does not support SetAmtOperationalState")
}

func TestDisableAMTCmd_Run_TransitionNotAllowed_ButSucceeds(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x82), nil) // 10000010 in binary - transition not allowed but AMT enabled
	mockAMT.EXPECT().DisableAMT().Return(nil)                                        // DisableAMT succeeds anyway (security operation)

	cmd := &DisableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.NoError(t, err) // Should succeed - disable is more permissive for security
}

func TestDisableAMTCmd_Run_TransitionNotAllowed_AndFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x82), nil) // 10000010 in binary
	mockAMT.EXPECT().DisableAMT().Return(errors.New("disable failed"))

	cmd := &DisableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to disable AMT")
}

func TestDisableAMTCmd_Run_DisableAMTError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x83), nil) // 10000011 in binary
	mockAMT.EXPECT().DisableAMT().Return(errors.New("disable failed"))

	cmd := &DisableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to disable AMT")
}

func TestDisableAMTCmd_Run_GetChangeEnabledError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), errors.New("connection failed"))

	cmd := &DisableAMTCmd{}
	ctx := &commands.Context{
		AMTCommand: mockAMT,
	}

	err := cmd.Run(ctx)
	assert.Error(t, err)
}
