/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// stubDial replaces statusDialTCP so reachability is decided by the provided set
// of addresses, with no real network access. It returns a restore function.
func stubDial(t *testing.T, reachable map[string]bool) {
	t.Helper()

	original := statusDialTCP
	statusDialTCP = func(address string, _ time.Duration) error {
		if reachable[address] {
			return nil
		}

		return errors.New("connection refused")
	}

	t.Cleanup(func() { statusDialTCP = original })
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	fn()

	w.Close()

	out, _ := io.ReadAll(r)
	os.Stdout = old

	return string(out)
}

func TestResolveHostTarget(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare host gets default port", "console.example.com", "console.example.com:443"},
		{"explicit port preserved", "console.example.com:8443", "console.example.com:8443"},
		{"trailing colon gets default", "console.example.com:", "console.example.com:443"},
		{"ipv4 with port", "10.0.0.5:16992", "10.0.0.5:16992"},
		{"bare ipv6 gets bracketed default", "::1", "[::1]:443"},
		{"whitespace trimmed", "  host.local  ", "host.local:443"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveHostTarget(tt.in))
		})
	}
}

func TestStatusCmd_Gather_Ready(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up", IPAddress: "192.168.1.10"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	stubDial(t, map[string]bool{
		"localhost:16992":         true,
		"console.example.com:443": true,
	})

	cmd := &StatusCmd{Host: "console.example.com"}
	cmd.HECIAvailable = true

	result, checks := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.True(t, result.MEIDriverPresent)
	assert.True(t, result.LMSInstalled)
	assert.True(t, result.WiredLinkUp)
	assert.False(t, result.WirelessLinkUp)
	require.NotNil(t, result.HostReachable)
	assert.True(t, *result.HostReachable)
	assert.True(t, result.ReadyToProvision, "at least one NIC up + LMS + MEI + host should be ready")

	// MEI, control mode, LMS, wired, wireless, host
	assert.Len(t, checks, 6)
}

func TestStatusCmd_Gather_NoLMS_StillReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	// Nothing reachable -> LMS not installed.
	stubDial(t, map[string]bool{})

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	result, checks := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.True(t, result.MEIDriverPresent)
	assert.False(t, result.LMSInstalled)
	// LMS no longer gates the verdict — the device is still provisionable.
	assert.True(t, result.ReadyToProvision)

	// The LMS row still reports a failed (X) state even though it doesn't block.
	for _, c := range checks {
		if strings.HasPrefix(c.label, "LMS") {
			assert.Equal(t, checkFail, c.state)
		}
	}
}

func TestStatusCmd_Gather_NotReady_NoNetwork(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	result, _ := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.True(t, result.LMSInstalled)
	assert.False(t, result.WiredLinkUp)
	assert.False(t, result.WirelessLinkUp)
	assert.False(t, result.ReadyToProvision, "both NICs down should not be ready")
}

func TestStatusCmd_Gather_HostUnreachable_ProvisionableNotManaged(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	// LMS reachable, host not.
	stubDial(t, map[string]bool{"localhost:16992": true})

	cmd := &StatusCmd{Host: "unreachable.example.com:8443"}
	cmd.HECIAvailable = true

	result, checks := cmd.gather(&Context{AMTCommand: mockAMT})

	require.NotNil(t, result.HostReachable)
	assert.False(t, *result.HostReachable)
	// Host gates manageability, not provisioning — the device is still provisionable.
	assert.True(t, result.ReadyToProvision)

	// The host row is a warning, not a failure.
	for _, c := range checks {
		if strings.HasPrefix(c.label, "Host reachable") {
			assert.Equal(t, checkWarn, c.state)
		}
	}
}

func TestStatusCmd_Run_TextProvisionableNotManaged(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})

	cmd := &StatusCmd{Host: "unreachable.example.com:8443"}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT})
		assert.NoError(t, err)
	})

	assert.Contains(t, out, verdictNotManaged)
}

func TestStatusCmd_Gather_NoMEI(t *testing.T) {
	stubDial(t, map[string]bool{"localhost:16992": true})

	cmd := &StatusCmd{}
	cmd.HECIAvailable = false

	// AMTCommand present but HECI unavailable -> link checks skipped, not called.
	result, checks := cmd.gather(&Context{})

	assert.False(t, result.MEIDriverPresent)
	assert.False(t, result.ReadyToProvision)
	// MEI, control mode, LMS, wired, wireless (no host)
	assert.Len(t, checks, 5)

	for _, c := range checks {
		if c.label == "Wired network link" || c.label == "Wireless network link" {
			assert.Equal(t, checkSkip, c.state)
		}
	}
}

func TestStatusCmd_Run_JSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up", IPAddress: "192.168.1.10"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT, JsonOutput: true})
		assert.NoError(t, err)
	})

	var result StatusResult
	require.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.True(t, result.MEIDriverPresent)
	assert.True(t, result.LMSInstalled)
	assert.True(t, result.WiredLinkUp)
	assert.True(t, result.ReadyToProvision)
}

func TestStatusCmd_Run_TextReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT})
		assert.NoError(t, err)
	})

	assert.Contains(t, out, "AMT Provisioning Readiness")
	assert.Contains(t, out, verdictReady)
}

func TestStatusCmd_Run_TextReadyNoLMS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	// LMS not reachable, but the device is otherwise ready.
	stubDial(t, map[string]bool{})

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT})
		assert.NoError(t, err)
	})

	assert.Contains(t, out, verdictReady)
	assert.Contains(t, out, "LMS features not available")
}

func TestStatusCmd_Gather_AlreadyActivated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true
	cmd.ControlMode = ControlModeACM // already activated

	result, _ := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.True(t, result.AlreadyActivated)
	assert.Equal(t, "admin control mode", result.ControlMode)
	assert.False(t, result.ReadyToProvision, "an activated device is not a provisioning candidate")
}

func TestStatusCmd_Run_TextAlreadyActivated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true
	cmd.ControlMode = ControlModeCCM

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT})
		assert.NoError(t, err)
	})

	assert.Contains(t, out, verdictAlreadyActive)
	assert.NotContains(t, out, verdictReady)
}

func TestVerdictColor(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name       string
		result     StatusResult
		elevated   bool
		amtCapable bool
		wantMsg    string
	}{
		{"no MEI, x86, elevated -> no AMT", StatusResult{MEIDriverPresent: false}, true, true, verdictNoAMT},
		{"no MEI, x86, unelevated -> unknown", StatusResult{MEIDriverPresent: false}, false, true, verdictUnknownPriv},
		{"no MEI, ARM, unelevated -> no AMT", StatusResult{MEIDriverPresent: false}, false, false, verdictNoAMT},
		{"no MEI, ARM, elevated -> no AMT", StatusResult{MEIDriverPresent: false}, true, false, verdictNoAMT},
		{"activated", StatusResult{MEIDriverPresent: true, AlreadyActivated: true}, true, true, verdictAlreadyActive},
		{"no network -> cannot", StatusResult{MEIDriverPresent: true, ReadyToProvision: false}, true, true, verdictCannotProvision},
		{
			"ready but host unreachable -> not managed",
			StatusResult{MEIDriverPresent: true, ReadyToProvision: true, HostReachable: boolPtr(false)},
			true,
			true,
			verdictNotManaged,
		},
		{"ready", StatusResult{MEIDriverPresent: true, ReadyToProvision: true}, true, true, verdictReady},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, msg := verdictColor(tt.result, tt.elevated, tt.amtCapable)
			assert.Equal(t, tt.wantMsg, msg)
		})
	}
}

func TestStatusCmd_RequiresAMTPassword(t *testing.T) {
	cmd := &StatusCmd{}
	assert.False(t, cmd.RequiresAMTPassword())
}
