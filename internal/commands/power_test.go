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

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/boot"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/power"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/service"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/software"
	ipspower "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/power"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func powerActionResponse(rv power.ReturnValue) power.Response {
	return power.Response{Body: power.Body{RequestPowerStateChangeResponse: power.PowerActionResponse{ReturnValue: rv}}}
}

func newPowerBase(t *testing.T) (AMTBaseCmd, *mock.MockWSMANer) {
	t.Helper()

	mockWSMAN := mock.NewMockWSMANer(gomock.NewController(t))

	return AMTBaseCmd{ControlMode: 1, WSMan: mockWSMAN}, mockWSMAN
}

func requireCode(t *testing.T, err error, code int) {
	t.Helper()

	var customErr utils.CustomError

	require.ErrorAs(t, err, &customErr)
	assert.Equal(t, code, customErr.Code)
}

func TestPowerCommandsRequireActivation(t *testing.T) {
	ctx := &Context{AMTPassword: "pw"}

	assert.Equal(t, utils.DeviceNotActivated, (&PowerStateCmd{}).Run(ctx))
	assert.Equal(t, utils.DeviceNotActivated, (&PowerCapabilitiesCmd{}).Run(ctx))
	assert.Equal(t, utils.DeviceNotActivated, (&PowerActionCmd{Action: "reset"}).Run(ctx))
}

func TestPowerStateCmd_Run(t *testing.T) {
	ctx := &Context{AMTPassword: "pw", JsonOutput: true}

	t.Run("success", func(t *testing.T) {
		base, m := newPowerBase(t)
		m.EXPECT().GetPowerState().Return([]service.CIM_AssociatedPowerManagementService{{PowerState: models.PowerState(2)}}, nil)
		m.EXPECT().GetOSPowerSavingState().Return(ipspower.FullPower, nil)

		assert.NoError(t, (&PowerStateCmd{AMTBaseCmd: base}).Run(ctx))
	})

	t.Run("empty state", func(t *testing.T) {
		base, m := newPowerBase(t)
		m.EXPECT().GetPowerState().Return(nil, nil)

		requireCode(t, (&PowerStateCmd{AMTBaseCmd: base}).Run(ctx), utils.WSMANMessageError.Code)
	})

	t.Run("OS power saving state error", func(t *testing.T) {
		base, m := newPowerBase(t)
		m.EXPECT().GetPowerState().Return([]service.CIM_AssociatedPowerManagementService{{PowerState: models.PowerState(2)}}, nil)
		m.EXPECT().GetOSPowerSavingState().Return(ipspower.Unknown, errors.New("boom"))

		requireCode(t, (&PowerStateCmd{AMTBaseCmd: base}).Run(ctx), utils.WSMANMessageError.Code)
	})
}

func TestPowerActionCmd_Run(t *testing.T) {
	ctx := &Context{AMTPassword: "pw", JsonOutput: true}

	t.Run("reset is sent straight to CIM without a state check", func(t *testing.T) {
		base, m := newPowerBase(t)
		m.EXPECT().RequestPowerStateChange(power.MasterBusReset).Return(powerActionResponse(0), nil)

		assert.NoError(t, (&PowerActionCmd{AMTBaseCmd: base, Action: "reset"}).Run(ctx))
	})

	t.Run("power_on brings the OS to full power first", func(t *testing.T) {
		base, m := newPowerBase(t)
		gomock.InOrder(
			m.EXPECT().GetOSPowerSavingState().Return(ipspower.OSPowerSaving, nil),
			m.EXPECT().RequestOSPowerSavingStateChange(ipspower.FullPower).Return(ipspower.PowerActionResponse{}, nil),
			m.EXPECT().RequestPowerStateChange(power.PowerOn).Return(powerActionResponse(0), nil),
		)

		assert.NoError(t, (&PowerActionCmd{AMTBaseCmd: base, Action: "power_on"}).Run(ctx))
	})

	t.Run("power_on aborts when the OS power state cannot be read", func(t *testing.T) {
		base, m := newPowerBase(t)
		m.EXPECT().GetOSPowerSavingState().Return(ipspower.Unknown, errors.New("boom"))

		requireCode(t, (&PowerActionCmd{AMTBaseCmd: base, Action: "power_on"}).Run(ctx), utils.WSMANMessageError.Code)
	})

	t.Run("os_to_power_saving uses IPS only", func(t *testing.T) {
		base, m := newPowerBase(t)
		m.EXPECT().GetOSPowerSavingState().Return(ipspower.FullPower, nil)
		m.EXPECT().RequestOSPowerSavingStateChange(ipspower.OSPowerSaving).Return(ipspower.PowerActionResponse{}, nil)

		assert.NoError(t, (&PowerActionCmd{AMTBaseCmd: base, Action: "os_to_power_saving"}).Run(ctx))
	})

	t.Run("os_to_full_power is a no-op when already at full power", func(t *testing.T) {
		base, m := newPowerBase(t)
		m.EXPECT().GetOSPowerSavingState().Return(ipspower.FullPower, nil)

		assert.NoError(t, (&PowerActionCmd{AMTBaseCmd: base, Action: "os_to_full_power"}).Run(ctx))
	})

	t.Run("non-zero return value is an error", func(t *testing.T) {
		base, m := newPowerBase(t)
		m.EXPECT().RequestPowerStateChange(power.PowerOffHard).Return(powerActionResponse(power.ReturnValueInvalidStateTransition), nil)

		requireCode(t, (&PowerActionCmd{AMTBaseCmd: base, Action: "power_off"}).Run(ctx), utils.WSMANMessageError.Code)
	})

	t.Run("unknown action", func(t *testing.T) {
		base, _ := newPowerBase(t)

		requireCode(t, (&PowerActionCmd{AMTBaseCmd: base, Action: "explode"}).Run(ctx), utils.InvalidUserInput.Code)
	})
}

func TestPowerActionNamesMatchConsole(t *testing.T) {
	want := map[string]int{
		"power_on": 2, "sleep": 4, "power_cycle": 5, "hibernate": 7, "power_off": 8, "power_off_soft": 9,
		"reset": 10, "soft_off": 12, "soft_reset": 14, "os_to_full_power": 500, "os_to_power_saving": 501,
	}

	assert.Equal(t, want, powerActionNames)
}

func TestPowerCapabilitiesCmd_Run(t *testing.T) {
	base, m := newPowerBase(t)
	m.EXPECT().GetAMTVersion().Return([]software.SoftwareIdentity{
		{InstanceID: "Flash", VersionString: "16.1.25"},
		{InstanceID: "AMT", VersionString: "16.1.25"},
	}, nil)
	m.EXPECT().GetBootCapabilities().Return(boot.BootCapabilitiesResponse{BIOSSetup: true}, nil)

	assert.NoError(t, (&PowerCapabilitiesCmd{AMTBaseCmd: base}).Run(&Context{AMTPassword: "pw", JsonOutput: true}))
}

func TestDeterminePowerCapabilities(t *testing.T) {
	t.Run("AMT 9 or older has only the basic actions", func(t *testing.T) {
		caps := determinePowerCapabilities(9, boot.BootCapabilitiesResponse{})

		assert.Equal(t, []string{"power_cycle", "power_off", "power_on", "reset"}, capabilityActionNames(caps))
		assert.Zero(t, caps.PowerOnToBIOS)
		assert.Zero(t, caps.PowerOnToDiagnostic)
		assert.Equal(t, 400, caps.ResetToPXE)
	})

	t.Run("newer AMT with BIOS setup, secure erase and diagnostics", func(t *testing.T) {
		caps := determinePowerCapabilities(16, boot.BootCapabilitiesResponse{BIOSSetup: true, SecureErase: true, ForceDiagnosticBoot: true})

		assert.Equal(t,
			[]string{"hibernate", "power_cycle", "power_off", "power_on", "reset", "sleep", "soft_off", "soft_reset"},
			capabilityActionNames(caps))
		assert.Equal(t, 101, caps.ResetToBIOS)
		assert.Equal(t, 104, caps.ResetToSecureErase)
		assert.Equal(t, 301, caps.ResetToDiagnostic)
	})

	t.Run("JSON uses Console keys", func(t *testing.T) {
		out, err := json.Marshal(determinePowerCapabilities(9, boot.BootCapabilitiesResponse{}))
		require.NoError(t, err)
		assert.Contains(t, string(out), `"Power up":2`)
		assert.NotContains(t, string(out), "Soft-off")
	})
}

func TestParseAMTMajorVersion(t *testing.T) {
	v, err := parseAMTMajorVersion([]software.SoftwareIdentity{{InstanceID: "AMT", VersionString: "12.0.45"}})
	require.NoError(t, err)
	assert.Equal(t, 12, v)

	_, err = parseAMTMajorVersion([]software.SoftwareIdentity{{InstanceID: "AMT", VersionString: "x.1"}})
	assert.Error(t, err)
}

func TestWritePowerOutput(t *testing.T) {
	result := PowerActionResult{Action: "reset", Code: 10}

	var buf bytes.Buffer

	require.NoError(t, writePowerOutput(&buf, true, result, func(io.Writer) { t.Fatal("text renderer called") }))

	var decoded map[string]any

	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Equal(t, "reset", decoded["action"])
	assert.InDelta(t, 10, decoded["code"], 0)
	assert.InDelta(t, 0, decoded["returnValue"], 0)
}
