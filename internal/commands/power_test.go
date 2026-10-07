/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/associatedpower"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/power"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func powerOnItems() []associatedpower.CIM_AssociatedPowerManagementService {
	return []associatedpower.CIM_AssociatedPowerManagementService{{
		PowerState:          models.PowerState(2),
		RequestedPowerState: models.RequestedPowerState(2),
		AvailableRequestedPowerStates: []models.AvailableRequestedPowerStates{
			models.AvailableRequestedPowerStates(power.PowerCycleOffHard),
			models.AvailableRequestedPowerStates(power.PowerOffHard),
			models.AvailableRequestedPowerStates(power.MasterBusReset),
		},
	}}
}

func powerActionResponse(rv power.ReturnValue) power.Response {
	return power.Response{Body: power.Body{RequestPowerStateChangeResponse: power.PowerActionResponse{ReturnValue: rv}}}
}

func TestNewPowerStateResult(t *testing.T) {
	item := powerOnItems()[0]

	result := newPowerStateResult(item.PowerState, item.RequestedPowerState, item.AvailableRequestedPowerStates)

	assert.Equal(t, PowerStateEntry{Value: 2, Name: "On"}, result.PowerState)
	assert.Equal(t, []string{"cycle", "off", "reset"}, result.AvailableActions)
	require.Len(t, result.AvailableRequestedPowerStates, 3)
	assert.Equal(t, "off", result.AvailableRequestedPowerStates[1].Action)
}

func TestPowerStateCmd_Run(t *testing.T) {
	t.Run("not activated", func(t *testing.T) {
		cmd := &PowerStateCmd{AMTBaseCmd: AMTBaseCmd{ControlMode: 0}}

		err := cmd.Run(&Context{AMTPassword: "pw"})
		assert.Equal(t, utils.DeviceNotActivated, err)
	})

	t.Run("wsman error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockWSMAN := mock.NewMockWSMANer(ctrl)
		mockWSMAN.EXPECT().GetPowerState().Return(nil, errors.New("boom"))

		cmd := &PowerStateCmd{AMTBaseCmd: AMTBaseCmd{ControlMode: 1, WSMan: mockWSMAN}}

		var customErr utils.CustomError

		err := cmd.Run(&Context{AMTPassword: "pw"})
		require.ErrorAs(t, err, &customErr)
		assert.Equal(t, utils.WSMANMessageError.Code, customErr.Code)
	})

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockWSMAN := mock.NewMockWSMANer(ctrl)
		mockWSMAN.EXPECT().GetPowerState().Return(powerOnItems(), nil)

		cmd := &PowerStateCmd{AMTBaseCmd: AMTBaseCmd{ControlMode: 2, WSMan: mockWSMAN}}

		assert.NoError(t, cmd.Run(&Context{AMTPassword: "pw", JsonOutput: true}))
	})
}

func TestPowerActionCmd_Run(t *testing.T) {
	tests := []struct {
		name     string
		state    string
		items    []associatedpower.CIM_AssociatedPowerManagementService
		expect   bool
		rv       power.ReturnValue
		wantCode int
	}{
		{name: "reset succeeds", state: "reset", items: powerOnItems(), expect: true, rv: power.ReturnValueCompletedWithNoError},
		{name: "state not available", state: "hibernate", items: powerOnItems(), wantCode: utils.InvalidUserInput.Code},
		{name: "non-zero return value", state: "off", items: powerOnItems(), expect: true, rv: power.ReturnValueInvalidStateTransition, wantCode: utils.WSMANMessageError.Code},
		{
			name:   "empty available list is not enforced",
			state:  "hibernate",
			items:  []associatedpower.CIM_AssociatedPowerManagementService{{PowerState: models.PowerState(2)}},
			expect: true,
			rv:     power.ReturnValueCompletedWithNoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockWSMAN := mock.NewMockWSMANer(ctrl)
			mockWSMAN.EXPECT().GetPowerState().Return(tt.items, nil)

			if tt.expect {
				mockWSMAN.EXPECT().RequestPowerStateChange(powerActions[tt.state]).Return(powerActionResponse(tt.rv), nil)
			}

			cmd := &PowerActionCmd{AMTBaseCmd: AMTBaseCmd{ControlMode: 1, WSMan: mockWSMAN}, State: tt.state}

			err := cmd.Run(&Context{AMTPassword: "pw", JsonOutput: true})
			if tt.wantCode == 0 {
				assert.NoError(t, err)

				return
			}

			var customErr utils.CustomError

			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, tt.wantCode, customErr.Code)
		})
	}
}

func TestWritePowerOutput(t *testing.T) {
	result := PowerActionResult{Action: "reset", PowerState: 10, Status: "success"}

	t.Run("json", func(t *testing.T) {
		var buf bytes.Buffer

		require.NoError(t, writePowerOutput(&buf, true, result, func(io.Writer) { t.Fatal("text renderer called") }))

		var decoded map[string]any

		require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
		assert.Equal(t, "reset", decoded["action"])
		assert.InDelta(t, 10, decoded["powerState"], 0)
		assert.Equal(t, "success", decoded["status"])
	})

	t.Run("text", func(t *testing.T) {
		var buf bytes.Buffer

		require.NoError(t, writePowerOutput(&buf, false, result, func(w io.Writer) { _, _ = io.WriteString(w, "text") }))
		assert.Equal(t, "text", buf.String())
	})
}
