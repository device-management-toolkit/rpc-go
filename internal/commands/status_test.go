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

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/environmentdetection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/managementpresence"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/remoteaccess"
	wsmantls "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/common"
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

func stubMonitor(t *testing.T, connected *bool) {
	t.Helper()

	original := statusDetectMonitorConnected
	statusDetectMonitorConnected = func() *bool {
		return connected
	}

	t.Cleanup(func() { statusDetectMonitorConnected = original })
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
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

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

	// MEI, BIOS, control mode, DNS suffix, device type, LMS, wired, wireless, host
	assert.Len(t, checks, 9)
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
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

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
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

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

	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

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
	// MEI, BIOS, control mode, DNS suffix, device type, LMS, wired, wireless (no host)
	assert.Len(t, checks, 8)

	for _, c := range checks {
		if c.label == "Wired network link" || c.label == "Wireless network link" ||
			c.label == "DNS suffix (AMT vs OS)" || c.label == "AMT device type" {
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
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

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

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT, JsonOutput: true})
		assert.NoError(t, err)
	})

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &payload))
	assert.Equal(t, "status", payload["command"])
	assert.Equal(t, "pre_activation", payload["selected_check_set"])
	assert.Equal(t, "pre_provisioning", payload["detected_state"])
	assert.Equal(t, "ready", payload["overall_result"])
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
	mockAMT.EXPECT().GetDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetOSDNSSuffix().Return("corp.local", nil)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)

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
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)
	mockAMT.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "outside enterprise (CIRA)",
		RemoteStatus:  "connected",
		MPSHostname:   "mps.example.com",
	}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubMonitor(t, nil)

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
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)
	mockAMT.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "outside enterprise (CIRA)",
		RemoteStatus:  "connected",
		MPSHostname:   "mps.example.com",
	}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubMonitor(t, nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true
	cmd.ControlMode = ControlModeCCM

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT})
		assert.NoError(t, err)
	})

	assert.Contains(t, out, "AMT Manageability Health")
	assert.Contains(t, out, "Selected checks")
	assert.NotContains(t, out, verdictReady)
	assert.Contains(t, out, "Local WSMAN session")
	assert.NotContains(t, out, "already activated (client control mode)")
	assert.Contains(t, out, "Evaluation: partial")
	assert.Contains(t, out, verdictPostPartial)
}

func TestStatusCmd_Run_JSON_PostActivationPartialWithoutPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetVersionDataFromME("Sku", meVersionTimeout).Return("8", nil)
	mockAMT.EXPECT().GetVersionDataFromME("AMT", meVersionTimeout).Return("16.1.0.0", nil)
	mockAMT.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "outside enterprise (CIRA)",
		RemoteStatus:  "connected",
		MPSHostname:   "mps.example.com",
	}, nil)

	stubDial(t, map[string]bool{"localhost:16992": true})
	stubMonitor(t, nil)

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true
	cmd.ControlMode = ControlModeCCM

	out := captureStdout(t, func() {
		err := cmd.Run(&Context{AMTCommand: mockAMT, JsonOutput: true})
		assert.NoError(t, err)
	})

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &payload))
	assert.Equal(t, "partial", payload["overall_result"])
	assert.Equal(t, true, payload["partialEvaluation"])
	assert.NotEmpty(t, payload["partialReason"])
}

func TestStatusCmd_Gather_PostActivationManageableWithWSMAN(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockWSMAN := mock.NewMockWSMANer(ctrl)

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

	mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
	mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)
	mockWSMAN.EXPECT().GetEnvironmentDetectionSettings().Return(environmentdetection.EnvironmentDetectionSettingDataResponse{
		DetectionStrings: []string{"corp.local"},
	}, nil)
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

	stubMonitor(t, boolPtr(true))

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

	assert.Equal(t, checkSkip, c.state)
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

	assert.Equal(t, checkFail, c.state)
	assert.False(t, result.DNSSuffixMatch)
	assert.Contains(t, c.detail, "amt.example.com")
	assert.Contains(t, c.detail, "os.example.com")
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

	cmd := &StatusCmd{}
	cmd.HECIAvailable = true

	var result StatusResult

	c := cmd.dnsSuffixCheck(&Context{AMTCommand: mockAMT}, &result)

	assert.Equal(t, checkWarn, c.state)
	assert.Contains(t, c.detail, "not configured")
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

	assert.Equal(t, checkWarn, c.state)
	assert.False(t, result.DNSSuffixMatch)
	assert.Contains(t, c.detail, "corp.example.com")
}

// ---------------------------------------------------------------------------
// deviceTypeCheck tests
// ---------------------------------------------------------------------------

func TestStatusCmd_DeviceTypeCheck_NoHECI(t *testing.T) {
	cmd := &StatusCmd{}
	cmd.HECIAvailable = false

	var result StatusResult

	c := cmd.deviceTypeCheck(&Context{}, &result)

	assert.Equal(t, checkSkip, c.state)
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

	assert.Equal(t, checkWarn, c.state)
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
