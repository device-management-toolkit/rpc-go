/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	wsmanboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/boot"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	wsmantls "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/common"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// stubDial replaces statusDialTCP so reachability is decided by the provided set
// of addresses, with no real network access. It restores the original dialer
// via t.Cleanup.
func stubDial(t *testing.T, reachable map[string]bool) {
	t.Helper()

	original := statusDialTCP
	statusDialTCP = func(address string, _ time.Duration) error {
		if reachable[address] {
			return nil
		}

		host, port, err := net.SplitHostPort(address)
		if err == nil {
			var altHost string

			switch host {
			case "localhost":
				altHost = "127.0.0.1"
			case "127.0.0.1":
				altHost = "localhost"
			}

			if altHost != "" && reachable[net.JoinHostPort(altHost, port)] {
				return nil
			}
		}

		return errors.New("connection refused")
	}

	t.Cleanup(func() { statusDialTCP = original })
}

func stubMonitor(t *testing.T, connected *bool) {
	t.Helper()

	original := statusDetectMonitorConnected
	statusDetectMonitorConnected = func() *bool {
		return connected
	}

	t.Cleanup(func() { statusDetectMonitorConnected = original })
}

// stubLMSVersion prevents real OS LMS queries (powershell/dpkg/systemctl) during tests.
func stubLMSVersion(t *testing.T, version string) {
	t.Helper()

	original := statusGetLMSVersion
	statusGetLMSVersion = func() string { return version }

	t.Cleanup(func() { statusGetLMSVersion = original })
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	defer func() {
		os.Stdout = old
	}()

	os.Stdout = w
	outCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	go func() {
		out, readErr := io.ReadAll(r)
		if readErr != nil {
			errCh <- readErr

			return
		}

		outCh <- out
	}()

	fn()

	require.NoError(t, w.Close())

	select {
	case readErr := <-errCh:
		require.NoError(t, readErr)

		return ""
	case out := <-outCh:
		require.NoError(t, r.Close())

		return string(out)
	}
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
		{"bracketed ipv6 gets default port", "[::1]", "[::1]:443"},
		{"bracketed ipv6 trailing colon gets default port", "[::1]:", "[::1]:443"},
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
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	stubDial(t, map[string]bool{
		"localhost:16992":         true,
		"console.example.com:443": true,
	})
	stubLMSVersion(t, "2406.0.0.0")

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

	assert.Len(t, checks, 10)
}

func TestStatusCmd_Gather_NoLMS_StillReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	// Nothing reachable -> LMS not installed.
	stubDial(t, map[string]bool{})
	stubLMSVersion(t, "")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	result, checks := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.True(t, result.MEIDriverPresent)
	assert.False(t, result.LMSInstalled)
	// LMS no longer gates the verdict — the device is still provisionable.
	assert.True(t, result.ReadyToProvision)

	// The LMS row is a warning and does not block readiness.
	for _, c := range checks {
		if strings.HasPrefix(c.label, "LMS") {
			assert.Equal(t, checkWarn, c.state)
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
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	result, _ := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.True(t, result.LMSInstalled)
	assert.False(t, result.WiredLinkUp)
	assert.False(t, result.WirelessLinkUp)
	assert.True(t, result.ReadyToProvision, "in auto profile, ACM-only network blockers should still allow CCM readiness")
}

func TestStatusCmd_Gather_HostUnreachable_ProvisionableNotManaged(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	// LMS reachable, host not.
	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "2406.0.0.0")

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

	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{Host: "unreachable.example.com:8443"}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT})
		assert.NoError(t, err)
	})

	assert.Contains(t, out, "Device is conditionally ready; activation can proceed with operational risks")
}

func TestStatusCmd_Gather_NoMEI(t *testing.T) {
	stubDial(t, map[string]bool{"localhost:16992": true})

	cmd := &StatusCmd{}
	cmd.HECIAvailable = false

	// AMTCommand present but HECI unavailable -> link checks skipped, not called.
	result, checks := cmd.gather(&Context{})

	assert.False(t, result.MEIDriverPresent)
	assert.False(t, result.ReadyToProvision)

	if utils.IsElevated() {
		// Elevated runs pass admin check, then fail at MEI driver check.
		assert.Len(t, checks, 2)
		assert.Equal(t, "Running as admin/root", checks[0].label)
		assert.Equal(t, checkPass, checks[0].state)
		assert.Equal(t, "MEI driver", checks[1].label)
		assert.Equal(t, checkFail, checks[1].state)

		return
	}

	// Non-elevated runs fail fast at admin check.
	assert.Len(t, checks, 1)
	assert.Equal(t, "Running as admin/root", checks[0].label)
	assert.Equal(t, checkFail, checks[0].state)
}

func TestStatusCmd_Run_FailsWithoutElevationWhenHECIUnavailable(t *testing.T) {
	if utils.IsElevated() {
		t.Skip("test validates non-elevated branch")
	}

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = false
	cmd.HECIError = ""

	err := cmd.Run(&Context{})
	assert.ErrorIs(t, err, utils.IncorrectPermissions)
}

func TestStatusCmd_Gather_NonVProFromHECIError(t *testing.T) {
	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = false
	cmd.HECIError = "inappropriate ioctl for device"

	result, checks := cmd.gather(&Context{})

	assert.True(t, result.MEIDriverPresent)
	assert.False(t, result.ReadyToProvision)
	assert.Len(t, checks, 3)
	assert.Equal(t, "Running as admin/root", checks[0].label)
	assert.Equal(t, checkPass, checks[0].state)
	assert.Equal(t, "MEI driver", checks[1].label)
	assert.Equal(t, checkPass, checks[1].state)
	assert.Equal(t, "Platform type", checks[2].label)
	assert.Equal(t, checkPass, checks[2].state)
	assert.Contains(t, checks[2].detail, "non-vPro")

	out := captureStdout(t, func() {
		renderStatus(os.Stdout, result, checks)
	})
	assert.Contains(t, out, "Platform type: non-vPro, contact Intel for manual checks")
	assert.Contains(t, out, "Device is not eligible for ACM activation.")
}

func TestStatusCmd_AdminCheck_MissingDriverErrorDoesNotBypassElevation(t *testing.T) {
	cmd := &StatusCmd{}
	cmd.HECIAvailable = false
	cmd.HECIError = "open /dev/mei0: no such file or directory"

	check := cmd.adminCheck()

	if utils.IsElevated() {
		assert.Equal(t, checkPass, check.state)

		return
	}

	assert.Equal(t, checkFail, check.state)
	assert.Contains(t, check.detail, "cannot access MEI")
}

func TestStatusCmd_MEICheck_MissingDriverErrorDoesNotPass(t *testing.T) {
	cmd := &StatusCmd{}
	cmd.HECIAvailable = false
	cmd.HECIError = "open /dev/mei0: no such file or directory"

	var result StatusResult

	check := cmd.meiCheck(&result)

	assert.Equal(t, checkFail, check.state)
	assert.False(t, result.MEIDriverPresent)

	if utils.IsElevated() {
		assert.Contains(t, check.detail, "Intel MEI driver not installed")

		return
	}

	assert.Contains(t, check.detail, "cannot access MEI")
}

func TestStatusCmd_Run_JSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up", IPAddress: "192.168.1.10"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT, JsonOutput: true})
		assert.NoError(t, err)
	})

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &payload))
	metadata, ok := payload["metadata"].(map[string]any)
	require.True(t, ok)
	evaluation, ok := payload["evaluation"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "status", metadata["command"])
	assert.Equal(t, "pre_activation", evaluation["selectedCheckSet"])
	assert.Equal(t, "pre_provisioning", evaluation["detectedState"])
	assert.Equal(t, "ready", evaluation["overallResult"])
}

func TestStatusCmd_Run_JSON_IncludesADRContract(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up", IPAddress: "192.168.1.10"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT, JsonOutput: true})
		assert.NoError(t, err)
	})

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &payload))
	metadata, ok := payload["metadata"].(map[string]any)
	require.True(t, ok)
	evaluation, ok := payload["evaluation"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "status", metadata["command"])
	assert.Equal(t, "pre_activation", evaluation["selectedCheckSet"])
	assert.Equal(t, "pre_provisioning", evaluation["detectedState"])
	assert.Equal(t, "ready", evaluation["overallResult"])

	checks, ok := payload["checks"].([]any)
	require.True(t, ok)
	assert.NotEmpty(t, checks)
}

func TestStatusCmd_Run_TextReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT})
		assert.NoError(t, err)
	})

	assert.Contains(t, out, "AMT Health Check")
	assert.Contains(t, out, "Device is ready for ACM activation")
}

func TestStatusCmd_Run_TextReadyNoLMS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).
		Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).
		Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	// LMS not reachable, but the device is otherwise ready.
	stubDial(t, map[string]bool{})
	stubLMSVersion(t, "")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT})
		assert.NoError(t, err)
	})

	assert.Contains(t, out, "Device is conditionally ready; activation can proceed with operational risks")
	assert.Contains(t, out, "LMS not installed. Install LMS")
}

func TestStatusCmd_Gather_AlreadyActivated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)
	mockAMT.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "outside enterprise (CIRA)",
		RemoteStatus:  "connected",
		MPSHostname:   "mps.example.com",
	}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubMonitor(t, nil)
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true
	cmd.ControlMode = ControlModeACM // already activated

	result, _ := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.True(t, result.AlreadyActivated)
	assert.Equal(t, "admin control mode", result.ControlMode)
	assert.Equal(t, "post_activation", result.SelectedCheckSet)
	assert.True(t, result.PartialEvaluation)
	assert.Contains(t, result.PartialReason, "WSMAN")
	assert.False(t, result.ReadyToProvision, "an activated device is not a provisioning candidate")
}

func TestStatusCmd_Run_TextAlreadyActivated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)
	mockAMT.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "outside enterprise (CIRA)",
		RemoteStatus:  "connected",
		MPSHostname:   "mps.example.com",
	}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubMonitor(t, nil)
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true
	cmd.ControlMode = ControlModeCCM

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT})
		assert.NoError(t, err)
	})

	assert.Contains(t, out, "AMT Health Check")
	assert.Contains(t, out, "Selected checks")
	assert.NotContains(t, out, "Device is ready for ACM activation")
	assert.Contains(t, out, "AMT password not provided; WSMAN-only checks skipped")
	assert.Contains(t, out, "Password context")
	assert.Contains(t, out, "Some prerequisites missing or not fully configured")
}

func TestStatusCmd_Run_JSON_PostActivationPartialWithoutPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)
	mockAMT.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "outside enterprise (CIRA)",
		RemoteStatus:  "connected",
		MPSHostname:   "mps.example.com",
	}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubMonitor(t, nil)
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true
	cmd.ControlMode = ControlModeCCM

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT, JsonOutput: true})
		assert.NoError(t, err)
	})

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &payload))
	evaluation, ok := payload["evaluation"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "partial", evaluation["overallResult"])
	assert.Equal(t, true, evaluation["partialEvaluation"])
	assert.NotEmpty(t, evaluation["partialReason"])
}

func TestStatusCmd_Gather_PostActivationManageableWithWSMAN(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

	mockAMT.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)
	mockAMT.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "direct connect",
		RemoteStatus:  "connected",
	}, nil)

	redirectionResponse := redirection.Response{
		Body: redirection.Body{
			GetAndPutResponse: redirection.RedirectionResponse{
				EnabledState:    2,
				ListenerEnabled: true,
			},
		},
	}

	mockWSMAN.EXPECT().EnumerateTLSSettingData().Return(wsmantls.Response{
		Body: wsmantls.Body{EnumerateResponse: common.EnumerateResponse{EnumerationContext: "tls-context"}},
	}, nil)
	mockWSMAN.EXPECT().PullTLSSettingData("tls-context").Return(wsmantls.Response{
		Body: wsmantls.Body{PullResponse: wsmantls.PullResponse{SettingDataItems: []wsmantls.SettingDataResponse{{
			InstanceID:                 "Intel(r) AMT 802.3 TLS Settings",
			Enabled:                    true,
			AcceptNonSecureConnections: false,
			MutualAuthentication:       false,
		}}}},
	}, nil)
	mockWSMAN.EXPECT().GetPublicKeyCerts().Return([]publickey.RefinedPublicKeyCertificateResponse{{
		TrustedRootCertificate: true,
	}}, nil)
	mockWSMAN.EXPECT().GetRedirectionService().Return(redirectionResponse, nil).Times(1)
	mockWSMAN.EXPECT().GetBootSettingData().Return(wsmanboot.Response{
		Body: wsmanboot.Body{BootSettingDataGetResponse: wsmanboot.BootSettingDataResponse{UEFIHTTPSBootEnabled: true}},
	}, nil)

	stubDial(t, map[string]bool{})
	stubMonitor(t, boolPtr(true))
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true
	cmd.ControlMode = ControlModeCCM
	cmd.WSMan = mockWSMAN

	result, checks := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.Equal(t, "post_activation", result.SelectedCheckSet)
	assert.True(t, result.ManageableInProduction)
	require.NotNil(t, result.WSMANAvailable)
	assert.True(t, *result.WSMANAvailable)
	assert.Equal(t, "Server", result.TLSMode)
	assert.Equal(t, "all", result.UserConsent)

	labels := make([]string, 0, len(checks))
	for _, c := range checks {
		labels = append(labels, c.label)
	}

	assert.Contains(t, labels, "AMT activated state")
	assert.NotContains(t, labels, "Control mode")
	assert.Contains(t, labels, "TLS configuration / trust inventory")
	assert.Contains(t, labels, "Redirection / consent baseline")
	assert.Contains(t, labels, "Management endpoint reachability")
}

func boolPtr(v bool) *bool {
	return &v
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

func TestFinalSummary_PreActivationDNSWarningMentionsCCM(t *testing.T) {
	result := StatusResult{SelectedCheckSet: checkSetPreActivation}
	checks := []healthCheck{{
		label:  "DNS suffix (AMT vs OS)",
		state:  checkWarn,
		detail: "AMT=example.com OS=corp.local (verify provisioning cert/profile domain alignment)",
	}}

	symbol, summary, next := finalSummary(result, checks)

	assert.Equal(t, "!", symbol)
	assert.Contains(t, summary, "CCM activation can proceed")
	assert.Contains(t, summary, "ACM requires DNS domain alignment")
	assert.Contains(t, next, "Proceed with CCM")
	assert.Contains(t, next, "re-run health check for ACM")
}

func TestFinalSummary_PreActivationACMDNSWarningMentionsACM(t *testing.T) {
	result := StatusResult{SelectedCheckSet: checkSetPreActivationACM}
	checks := []healthCheck{{
		label:  "DNS suffix (AMT vs OS)",
		state:  checkWarn,
		detail: "AMT=example.com OS=corp.local (verify provisioning cert/profile domain alignment)",
	}}

	symbol, summary, next := finalSummary(result, checks)

	assert.Equal(t, "!", symbol)
	assert.Contains(t, summary, "ACM activation requires DNS domain alignment")
	assert.NotContains(t, summary, "CCM activation")
	assert.Contains(t, next, "ACM")
	assert.NotContains(t, next, "CCM")
}

func TestFinalSummary_PreActivationACMOnlyFailuresMentionsCCMPath(t *testing.T) {
	result := StatusResult{SelectedCheckSet: checkSetPreActivation}
	checks := []healthCheck{
		{label: "DNS suffix (AMT vs OS)", state: checkFail, detail: "DNS suffix not configured - cannot activate to ACM"},
		{label: "AMT wired/wireless link", state: checkFail, detail: "Wired link down and no AMT DNS suffix"},
	}

	symbol, summary, next := finalSummary(result, checks)

	assert.Equal(t, "!", symbol)
	assert.Contains(t, summary, "CCM activation can still proceed")
	assert.Contains(t, next, "Proceed with CCM")
	assert.Contains(t, next, "re-run health check for ACM")
}

func TestFinalSummary_PreActivationCCMBypassWarningsProceeds(t *testing.T) {
	result := StatusResult{SelectedCheckSet: checkSetPreActivationCCM}
	checks := []healthCheck{
		{label: "DNS suffix (AMT vs OS)", state: checkWarn, detail: "DNS suffix not configured - cannot activate to ACM (ACM-only blocker; CCM can still proceed)"},
		{label: "AMT wired/wireless link", state: checkWarn, detail: "No AMT network link detected (ACM would require wired link; CCM can still proceed locally)"},
	}

	symbol, summary, next := finalSummary(result, checks)

	assert.Equal(t, "✓", symbol)
	assert.Contains(t, summary, "ready for CCM activation")
	assert.Contains(t, next, "Proceed with CCM activation")
}

func TestStatusCmd_RequiresAMTPassword(t *testing.T) {
	cmd := &StatusCmd{}
	assert.False(t, cmd.RequiresAMTPassword())
}

// ---------------------------------------------------------------------------
// dnsSuffixCheck tests
// ---------------------------------------------------------------------------

func TestStatusCmd_DNSSuffixCheck_NoHECI(t *testing.T) {
	cmd := &StatusCmd{}
	cmd.HECIAvailable = false

	var result StatusResult

	c := cmd.dnsSuffixCheck(&Context{}, &result)

	assert.Equal(t, checkUnavailable, c.state)
	assert.False(t, result.DNSSuffixMatch)
}

func TestStatusCmd_DNSSuffixCheck_Match(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.example.com", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("CORP.EXAMPLE.COM", nil) // case-insensitive

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.dnsSuffixCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkPass, c.state)
	assert.True(t, result.DNSSuffixMatch)
	assert.Contains(t, c.detail, "corp.example.com")
}

func TestStatusCmd_DNSSuffixCheck_Mismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetDNSSuffix().Return("amt.example.com", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("os.example.com", nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.dnsSuffixCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkWarn, c.state)
	assert.False(t, result.DNSSuffixMatch)
	assert.Contains(t, c.detail, "amt.example.com")
	assert.Contains(t, c.detail, "os.example.com")
	assert.Contains(t, c.detail, "cert/profile")
}

func TestStatusCmd_DNSSuffixCheck_AMTSuffixError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetDNSSuffix().Return("", errors.New("heci read error"))

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.dnsSuffixCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkWarn, c.state)
	assert.False(t, result.DNSSuffixMatch)
}

func TestStatusCmd_DNSSuffixCheck_AMTSuffixEmpty(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetDNSSuffix().Return("", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.dnsSuffixCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkFail, c.state)
	assert.Contains(t, c.detail, "not configured")
}

func TestStatusCmd_DNSSuffixCheckForProfile_MissingSuffixWarnsForAutoAndCCM(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetDNSSuffix().Return("", nil).Times(2)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil).Times(2)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	autoCheck := cmd.dnsSuffixCheckForProfile(&Context{AMTCommand: mockAMT}, &StatusResult{}, statusProfileAuto)
	ccmCheck := cmd.dnsSuffixCheckForProfile(&Context{AMTCommand: mockAMT}, &StatusResult{}, statusProfileCCM)

	assert.Equal(t, checkWarn, autoCheck.state)
	assert.Contains(t, autoCheck.detail, "ACM-only blocker")
	assert.Equal(t, checkWarn, ccmCheck.state)
	assert.Contains(t, ccmCheck.detail, "CCM can still proceed")
}

func TestStatusCmd_DNSSuffixCheckForProfile_MissingSuffixRemainsFailForACM(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetDNSSuffix().Return("", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	check := cmd.dnsSuffixCheckForProfile(&Context{AMTCommand: mockAMT}, &StatusResult{}, statusProfileACM)

	assert.Equal(t, checkFail, check.state)
	assert.NotContains(t, check.detail, "CCM can still proceed")
}

func TestStatusCmd_DNSSuffixCheck_AMTSuffixEmptyWithOSSuffixPresent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetDNSSuffix().Return("", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.example.com", nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.dnsSuffixCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkFail, c.state)
	assert.Contains(t, c.detail, "AMT DNS suffix not configured")
}

func TestStatusCmd_DNSSuffixCheck_OSSuffixUnknown(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.example.com", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil) // empty — not joined to domain

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.dnsSuffixCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkPass, c.state)
	assert.False(t, result.DNSSuffixMatch)
	assert.Contains(t, c.detail, "corp.example.com")
}

func TestStatusCmd_LinkReadiness_WirelessUpStillFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "up"}, nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	result := StatusResult{AMTDNSSuffix: "corp.example.com"}

	c := cmd.linkReadinessCheck(&Context{AMTCommand: mockAMT}, &result, statusProfileACM)

	assert.Equal(t, checkFail, c.state)
	assert.Contains(t, c.detail, "Wired link is down")
	assert.False(t, result.WiredLinkUp)
	assert.True(t, result.WirelessLinkUp)
}

func TestStatusCmd_LinkReadiness_CCMProfile_DoesNotFailWhenNoLink(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	result := StatusResult{}

	c := cmd.linkReadinessCheck(&Context{AMTCommand: mockAMT}, &result, statusProfileCCM)

	assert.Equal(t, checkWarn, c.state)
	assert.Contains(t, c.detail, "CCM can still proceed locally")
}

func TestStatusCmd_Gather_CCMProfile_DoesNotBlockOnACMChecks(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{CCM: true}
	cmd.HECIAvailable = true

	result, checks := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.Equal(t, checkSetPreActivationCCM, result.SelectedCheckSet)
	assert.True(t, result.ReadyToProvision)

	for _, c := range checks {
		if c.label == "DNS suffix (AMT vs OS)" {
			assert.Equal(t, checkWarn, c.state)
		}
	}
}

func TestStatusCmd_Gather_AutoProfile_AllowsCCMWhenOnlyACMChecksFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "2406.0.0.0")

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	result, checks := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.Equal(t, checkSetPreActivation, result.SelectedCheckSet)
	assert.True(t, result.ReadyToProvision)

	for _, c := range checks {
		if c.label == linkReadinessCheckLabel {
			assert.Equal(t, checkFail, c.state)
		}
	}
}

func TestStatusCmd_Gather_ACMProfile_BlocksOnACMChecks(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)
	mockAMT.EXPECT().GetDNSSuffix().Return("", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubLMSVersion(t, "")

	cmd := &StatusCmd{ACM: true}
	cmd.HECIAvailable = true

	result, _ := cmd.gather(&Context{AMTCommand: mockAMT})

	assert.Equal(t, checkSetPreActivationACM, result.SelectedCheckSet)
	assert.False(t, result.ReadyToProvision)
}

func TestStatusCmd_PreparePostActivationWSMAN_ClearsClientOnSetupError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)
	mockWSMAN.EXPECT().SetupWsmanClient("admin", "secret", false, false, gomock.Any()).Return(errors.New("setup failed"))

	originalFactory := newWSMANClient
	newWSMANClient = func(string) interfaces.WSMANer { return mockWSMAN }

	t.Cleanup(func() { newWSMANClient = originalFactory })

	cmd := &StatusCmd{}
	cmd.preparePostActivationWSMAN(&Context{AMTPassword: "secret"})

	assert.Nil(t, cmd.WSMan)
	assert.Equal(t, "could not initialize WSMAN client", cmd.wsmanStatusDetail)
}

func TestStatusCmd_ConnectionModeCheck_DirectModeDoesNotSetCIRAConnected(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "direct connect",
		RemoteStatus:  "connected",
	}, nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.connectionModeCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkPass, c.state)
	assert.Equal(t, connectionModeDirect, result.ConnectionMode)
	assert.Nil(t, result.CIRAConnected, "CIRAConnected must stay nil in Direct mode")
}

func TestStatusCmd_RemoteManageabilityCheck_UserHostNotOverriddenByCIRA(t *testing.T) {
	stubDial(t, map[string]bool{}) // all dials fail

	cmd := &StatusCmd{Host: "console.example.com:443"}
	result := &StatusResult{
		ConnectionMode: "CIRA",
		CIRAConnected:  ptrBool(true),
		MPSHostname:    "mps.example.com",
	}

	check := cmd.remoteManageabilityCheck(result)

	// The --host target failed the TCP probe; the CIRA tunnel must NOT mask that.
	assert.Equal(t, checkFail, check.state)
	assert.Contains(t, check.detail, "unreachable")
	require.NotNil(t, result.RemoteManageabilityUp)
	assert.False(t, *result.RemoteManageabilityUp, "CIRA tunnel must not override a user-supplied --host failure")
}

func TestStatusCmd_ModeAlignmentCheck_PostActivationCCMMismatchFails(t *testing.T) {
	cmd := &StatusCmd{}

	check := cmd.modeAlignmentCheck(statusProfileCCM, StatusResult{ControlMode: "admin control mode"})

	assert.Equal(t, checkFail, check.state)
	assert.Contains(t, check.detail, "--ccm/--cm requested")
}

func TestStatusCmd_Validate_RejectsConflictingProfiles(t *testing.T) {
	cmd := &StatusCmd{ACM: true, CCM: true}

	err := cmd.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be used together")
}

// ---------------------------------------------------------------------------
// deviceTypeCheck tests
// ---------------------------------------------------------------------------

func TestStatusCmd_DeviceTypeCheck_NoHECI(t *testing.T) {
	cmd := &StatusCmd{}
	cmd.HECIAvailable = false

	var result StatusResult

	c := cmd.deviceTypeCheck(&Context{}, &result)

	assert.Equal(t, checkUnavailable, c.state)
	assert.Empty(t, result.DeviceType)
}

func TestStatusCmd_DeviceTypeCheck_VPro(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	// SKU 0x8 sets bit 3 → "AMT Pro" for AMT v5+
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.deviceTypeCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkPass, c.state)
	assert.Contains(t, result.DeviceType, "AMT Pro")
	assert.Contains(t, c.detail, "vPro")
}

func TestStatusCmd_DeviceTypeCheck_ISM(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	// SKU 0x10 sets bit 4 → "Intel Standard Manageability" for AMT v5+
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("16", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.deviceTypeCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkPass, c.state)
	assert.Contains(t, result.DeviceType, "Intel Standard Manageability")
	assert.Contains(t, c.detail, "ISM")
}

func TestStatusCmd_DeviceTypeCheck_SKUError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("", errors.New("heci error"))

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.deviceTypeCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkWarn, c.state)
	assert.Empty(t, result.DeviceType)
}

func TestStatusCmd_DeviceTypeCheck_VersionError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("", errors.New("heci error"))

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.deviceTypeCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkWarn, c.state)
	assert.Empty(t, result.DeviceType)
}
