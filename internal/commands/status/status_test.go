/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	amttls "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	cimkvm "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/kvm"
	ipsoptin "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/optin"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	localamt "github.com/device-management-toolkit/rpc-go/v2/internal/local/amt"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestEvaluateVerdict(t *testing.T) {
	tests := []struct {
		name   string
		checks []Check
		result string
		ready  bool
	}{
		{
			name:   "all pass",
			checks: []Check{{ID: checkIDMEI, Status: checkPass}},
			result: resultReady,
			ready:  true,
		},
		{
			name:   "warning is conditional",
			checks: []Check{{ID: checkIDDNS, Status: checkWarn}},
			result: resultConditional,
			ready:  true,
		},
		{
			name:   "DNS suffix difference remains conditional",
			checks: []Check{{ID: checkIDDNS, Status: checkWarn, Message: "AMT DNS suffix (corp.example.com) differs from host DNS suffix (host.example.com). Confirm this matches your provisioning setup"}},
			result: resultConditional,
			ready:  true,
		},
		{
			name:   "failure blocks readiness",
			checks: []Check{{ID: checkIDNetwork, Status: checkFail}},
			result: resultNotReady,
		},
		{
			name: "known blocker takes precedence over unavailable checks",
			checks: []Check{
				{ID: checkIDNetwork, Status: checkFail},
				{ID: checkIDDNS, Status: checkUnavailable},
			},
			result: resultNotReady,
		},
		{
			name:   "unavailable checks leave result unknown",
			checks: []Check{{ID: checkIDMEI, Status: checkUnavailable}},
			result: "unknown",
		},
		{
			name:   "activated devices await post activation checks",
			checks: []Check{{ID: checkIDActivation, Status: checkAlreadyActive}, {ID: checkIDPostHealth, Status: checkNotEvaluated}},
			result: "not_evaluated",
		},
		{
			name:   "missing MEI means not AMT",
			checks: []Check{{ID: checkIDMEI, Status: checkFail}},
			result: resultNotAMT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateVerdict(tt.checks)

			assert.Equal(t, tt.result, got.Result)
			assert.Equal(t, tt.ready, got.ReadyToProvision)
		})
	}
}

func TestPostActivationFailureVerdictUsesManagementWording(t *testing.T) {
	verdict := EvaluateVerdict([]Check{
		{ID: checkIDWSMAN, Status: checkPass},
		{ID: checkIDRedirection, Status: checkFail},
	})

	assert.Equal(t, resultNotReady, verdict.Result)
	assert.Equal(t, "Device is not ready for remote management", verdict.Status)
}

func TestPostActivationOperationalStateIsVersionGated(t *testing.T) {
	monitorConnected := true
	legacyUnsupported := false
	newInterfaceSupported := true
	tests := []struct {
		name        string
		version     string
		supported   *bool
		wantCheck   bool
		wantVerdict string
	}{
		{name: "AMT 11 does not require unsupported read", version: "11.8.50", wantVerdict: resultReady},
		{name: "AMT 12 failed query remains unavailable", version: "12.0.0", wantCheck: true, wantVerdict: resultUnknown},
		{name: "AMT 12 legacy interface is omitted", version: "12.0.0", supported: &legacyUnsupported, wantVerdict: resultReady},
		{name: "AMT 12 new interface requires the state read", version: "12.0.0", supported: &newInterfaceSupported, wantCheck: true, wantVerdict: resultUnknown},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := &commands.InfoSnapshot{
				Info: &commands.InfoResult{
					ControlMode: "client control mode", ProvisioningState: "post-provisioning", Features: "AMT Pro Corporate", AMT: test.version, SKU: "16392",
					DNSSuffix: "corp.example.com", DNSSuffixOS: "corp.example.com",
					RAS:             &amt.RemoteAccessStatus{NetworkStatus: "direct (LAN)", RemoteStatus: "connected"},
					WiredAdapter:    &amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"},
					WirelessAdapter: &amt.InterfaceSettings{LinkStatus: "down"},
				},
				AMTDNSSuffixRead: true, OSDNSSuffixRead: true, ProvisioningStateRead: true, OperationalStateRead: false,
				OperationalStateSupported: test.supported, TLSMode: "Server",
				PostActivation: &commands.PostActivationSnapshot{
					WSMANStatus: commands.WSMANStatusAvailable, TLSModeRead: true,
					KVMRead: true, KVMState: "enabled",
					RedirectionRead: true, RedirectionState: "32771", RedirectionListenerEnabled: true,
					UserConsentRead: true, UserConsent: "none", MonitorConnected: &monitorConnected,
				},
			}

			checks := postActivationChecks(&StatusCmd{}, snapshot)

			var operationalCheck *Check

			for index := range checks {
				if checks[index].ID == checkIDOperationalState {
					operationalCheck = &checks[index]

					break
				}
			}

			if test.wantCheck {
				require.NotNil(t, operationalCheck)
				assert.Equal(t, checkUnavailable, operationalCheck.Status)
			} else {
				assert.Nil(t, operationalCheck)
			}

			assert.Equal(t, test.wantVerdict, EvaluateVerdict(checks).Result)
		})
	}
}

func TestDisabledOperationalStateBlocksPostActivationReadiness(t *testing.T) {
	check := operationalStatePostCheck(stateDisabled, true)
	assert.Equal(t, checkFail, check.Status)

	verdict := EvaluateVerdict([]Check{
		{ID: checkIDWSMAN, Status: checkUnavailable},
		check,
	})
	assert.Equal(t, resultNotReady, verdict.Result)
}

func TestInfoSnapshotRecordsLegacyOperationalStateAsUnsupported(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	amtCommand.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("12.0.0.0", nil)
	amtCommand.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("16392", nil)
	amtCommand.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x02), nil)

	controlMode := commands.ControlModeCCM
	service := commands.NewInfoService(
		amtCommand,
		commands.WithHECIAvailable(true),
		commands.WithCachedControlMode(controlMode),
	)
	snapshot := service.GetInfoSnapshot(&commands.AmtInfoCmd{Ver: true, Sku: true, OpState: true}, false)

	require.NotNil(t, snapshot.OperationalStateSupported)
	assert.False(t, *snapshot.OperationalStateSupported)
	assert.False(t, snapshot.OperationalStateRead)
	assert.Empty(t, snapshot.Info.OperationalState)
}

func TestRequestedPostActivationModeMismatchFailsReadiness(t *testing.T) {
	tests := []struct {
		name       string
		cmd        *StatusCmd
		actualMode string
		message    string
	}{
		{
			name:       "ACM requested for CCM device",
			cmd:        &StatusCmd{ACM: true, AMTBaseCmd: commands.AMTBaseCmd{ControlMode: commands.ControlModeCCM}},
			actualMode: "client control mode",
			message:    "--acm was requested",
		},
		{
			name:       "CCM requested for ACM device",
			cmd:        &StatusCmd{CCM: true, AMTBaseCmd: commands.AMTBaseCmd{ControlMode: commands.ControlModeACM}},
			actualMode: "admin control mode",
			message:    "--ccm was requested",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			check, ok := requestedPostActivationModeCheck(test.cmd, test.actualMode)
			require.True(t, ok)
			assert.Equal(t, checkFail, check.Status)
			assert.Contains(t, check.Message, test.message)

			verdict := EvaluateVerdict([]Check{{ID: checkIDWSMAN, Status: checkPass}, check})
			assert.Equal(t, resultNotReady, verdict.Result)
		})
	}
}

func TestVerdictErrorUsesCustomExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		result   string
		wantCode int
	}{
		{name: "not ready", result: resultNotReady, wantCode: utils.AmtNotReady.Code},
		{name: "not AMT", result: resultNotAMT, wantCode: utils.AmtNotDetected.Code},
		{name: "unknown", result: resultUnknown, wantCode: utils.GenericFailure.Code},
		{name: "conditional is successful", result: resultConditional},
		{name: "ready is successful", result: resultReady},
		{name: "not evaluated is successful", result: "not_evaluated"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verdictError(Verdict{Result: tt.result})
			if tt.wantCode == 0 {
				require.NoError(t, err)

				return
			}

			var customErr utils.CustomError
			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, tt.wantCode, customErr.Code)
		})
	}
}

func TestEvaluateUnknownWhenNotElevated(t *testing.T) {
	checks := initialChecks(false, false, nil, "")
	checks = append(checks, Check{
		ID: checkIDActivation, Name: checkNameActivation, Status: checkUnavailable,
		Message: "AMT state unknown; run as administrator",
	})

	verdict := EvaluateVerdict(checks)

	assert.Equal(t, resultUnknown, verdict.Result)
	assert.Equal(t, "AMT status unknown (run as administrator)", verdict.Status)
	assert.False(t, verdict.ReadyToProvision)
}

func TestInitialChecksIncludesMEIDriverVersion(t *testing.T) {
	checks := initialChecks(true, true, nil, "7.0.0-28-generic")

	assert.Equal(t, "MEI/HECI driver is responding (version 7.0.0-28-generic)", checks[1].Message)
}

func TestInitialChecksKeepTransientHECIProbeFailuresUnknown(t *testing.T) {
	checks := initialChecks(true, false, errors.New("ME remains busy"), "")
	verdict := EvaluateVerdict(checks)

	assert.Equal(t, checkUnavailable, checks[1].Status)
	assert.Equal(t, resultUnknown, verdict.Result)
	assert.NotContains(t, checks[1].Message, "not found")
}

func TestInitialChecksFailOnlyForConfirmedHECIAbsence(t *testing.T) {
	for _, probeErr := range []error{heci.ErrDeviceNotFound, heci.ErrUnsupportedDevice} {
		checks := initialChecks(true, false, probeErr, "")
		assert.Equal(t, checkFail, checks[1].Status)
	}
}

func TestLMSCheckIncludesVersionWhenReachable(t *testing.T) {
	oldDetectLMS := statusDetectLMS
	oldGetLMSVersion := statusGetLMSVersion
	statusDetectLMS = func(bool) bool { return true }
	statusGetLMSVersion = func() string { return "2406.0.0.0" }

	t.Cleanup(func() {
		statusDetectLMS = oldDetectLMS
		statusGetLMSVersion = oldGetLMSVersion
	})

	check := lmsCheck(false)

	assert.Equal(t, checkPass, check.Status)
	assert.Equal(t, "Local Manageability Service is listening (version 2406.0.0.0)", check.Message)
}

func expectStatusWSMAN(wsman *mock.MockWSMANer) {
	wsman.EXPECT().GetGeneralSettings().Return(general.Response{}, nil)
	wsman.EXPECT().GetKVMRedirectionSAP().Return(cimkvm.Response{Body: cimkvm.Body{
		GetResponse: cimkvm.KVMRedirectionSAP{EnabledState: cimkvm.EnabledStateEnabled},
	}}, nil)
	wsman.EXPECT().GetRedirectionService().Return(redirection.Response{Body: redirection.Body{
		GetAndPutResponse: redirection.RedirectionResponse{EnabledState: redirection.IDERAndSOLAreEnabled, ListenerEnabled: true},
	}}, nil)
	wsman.EXPECT().GetIpsOptInService().Return(ipsoptin.Response{Body: ipsoptin.Body{
		GetAndPutResponse: ipsoptin.OptInServiceResponse{OptInRequired: uint32(ipsoptin.OptInRequiredNone)},
	}}, nil)
	wsman.EXPECT().EnumerateTLSSettingData().Return(amttls.Response{}, nil)
	wsman.EXPECT().PullTLSSettingData("").Return(amttls.Response{}, nil)
}

func TestRedirectionStateDoesNotImplyKVMEnabled(t *testing.T) {
	snapshot := &commands.PostActivationSnapshot{
		RedirectionRead: true, RedirectionState: "32770", RedirectionListenerEnabled: true,
		KVMRead: true, KVMState: "disabled",
	}

	assert.Equal(t, checkPass, redirectionCheck(snapshot).Status)
	assert.Equal(t, checkPass, solCheck(snapshot).Status)
	assert.Equal(t, checkWarn, kvmCheck(snapshot).Status)
}

func TestKVMOnlyConfigurationIsReadyWhenSOLAndIDERAreDisabled(t *testing.T) {
	snapshot := &commands.PostActivationSnapshot{
		RedirectionRead: true, RedirectionState: "32768", RedirectionListenerEnabled: true,
		KVMRead: true, KVMState: "enabled",
	}
	checks := []Check{
		{ID: checkIDWSMAN, Status: checkPass},
		redirectionCheck(snapshot),
		solCheck(snapshot),
		kvmCheck(snapshot),
	}

	assert.Equal(t, checkWarn, checks[1].Status)
	assert.Equal(t, checkWarn, checks[2].Status)
	assert.Equal(t, checkPass, checks[3].Status)
	verdict := EvaluateVerdict(checks)
	assert.Equal(t, resultReady, verdict.Result)
	assert.True(t, verdict.ReadyForManagement)
}

func TestSOLCheckUsesRedirectionEnum(t *testing.T) {
	tests := []struct {
		name     string
		state    string
		listener bool
		status   checkState
	}{
		{name: "SOL only", state: "32770", listener: true, status: checkPass},
		{name: "SOL and IDER", state: "32771", listener: true, status: checkPass},
		{name: "IDER only", state: "32769", listener: true, status: checkWarn},
		{name: "both disabled", state: "32768", listener: true, status: checkWarn},
		{name: "listener disabled", state: "32770", status: checkFail},
		{name: "state unreadable", status: checkUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := &commands.PostActivationSnapshot{
				RedirectionRead: test.state != "", RedirectionState: test.state,
				RedirectionListenerEnabled: test.listener,
			}
			assert.Equal(t, test.status, solCheck(snapshot).Status)
		})
	}
}

func TestISMPostActivationSkipsKVMRequestAndCheck(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	wsman := mock.NewMockWSMANer(ctrl)
	wsman.EXPECT().GetGeneralSettings().Return(general.Response{}, nil)
	wsman.EXPECT().GetRedirectionService().Return(redirection.Response{Body: redirection.Body{
		GetAndPutResponse: redirection.RedirectionResponse{EnabledState: redirection.IDERAndSOLAreEnabled, ListenerEnabled: true},
	}}, nil)
	wsman.EXPECT().GetIpsOptInService().Return(ipsoptin.Response{Body: ipsoptin.Body{
		GetAndPutResponse: ipsoptin.OptInServiceResponse{OptInRequired: uint32(ipsoptin.OptInRequiredNone)},
	}}, nil)
	wsman.EXPECT().EnumerateTLSSettingData().Return(amttls.Response{}, nil)
	wsman.EXPECT().PullTLSSettingData("").Return(amttls.Response{
		Body: amttls.Body{PullResponse: amttls.PullResponse{SettingDataItems: []amttls.SettingDataResponse{{
			InstanceID: "AMT 802.3 TLS Settings", Enabled: true,
		}}}},
	}, nil)
	amtCommand.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("16.1.25", nil)
	amtCommand.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("16400", nil)
	amtCommand.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x82), nil)
	amtCommand.EXPECT().GetProvisioningState().Return(2, nil)
	amtCommand.EXPECT().GetDNSSuffix().Return("corp.example.com", nil)
	amtCommand.EXPECT().GetOSDNSSuffix().Return("corp.example.com", nil)
	amtCommand.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "direct (LAN)", RemoteStatus: "connected",
	}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{
		HECIAvailable: true, ControlMode: commands.ControlModeCCM, WSMan: wsman,
	}}
	result := cmd.evaluate(&commands.Context{AMTCommand: amtCommand})

	assert.Contains(t, result.DeviceType, deviceTypeISM)

	for _, check := range result.Checks {
		assert.NotEqual(t, checkIDKVM, check.ID)
	}
}

func TestTrustedRootsRequirementsFollowTLSMode(t *testing.T) {
	snapshot := &commands.PostActivationSnapshot{TrustedRootInventoryRead: true}
	tests := []struct {
		mode         string
		status       checkState
		requiredRoot bool
	}{
		{mode: "Server", status: checkNotEvaluated},
		{mode: "ServerAndNonTLS", status: checkNotEvaluated},
		{mode: "Mutual", status: checkFail, requiredRoot: true},
		{mode: "MutualAndNonTLS", status: checkFail, requiredRoot: true},
		{mode: "None", status: checkNotEvaluated},
	}

	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			assert.Equal(t, test.status, trustedRootsCheck(test.mode, snapshot).Status)
			assert.Equal(t, test.requiredRoot, tlsRequiresTrustedRoots(test.mode))
		})
	}
}

func TestPostActivationChecksSkipTrustedRootsForServerTLS(t *testing.T) {
	monitorConnected := true
	snapshot := &commands.InfoSnapshot{
		Info: &commands.InfoResult{
			ControlMode: "client control mode", Features: "AMT Pro Corporate", AMT: "16.1.25", SKU: "16392",
			DNSSuffix: "example.com", DNSSuffixOS: "example.com", OperationalState: "enabled",
			RAS:             &amt.RemoteAccessStatus{NetworkStatus: "direct (LAN)", RemoteStatus: "connected"},
			WiredAdapter:    &amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"},
			WirelessAdapter: &amt.InterfaceSettings{LinkStatus: "down"},
		},
		AMTDNSSuffixRead: true, OSDNSSuffixRead: true, ProvisioningStateRead: true, OperationalStateRead: true, TLSMode: "Server",
		PostActivation: &commands.PostActivationSnapshot{
			WSMANStatus: commands.WSMANStatusAvailable, TLSModeRead: true,
			KVMRead: true, KVMState: "enabled",
			RedirectionRead: true, RedirectionState: "32771", RedirectionListenerEnabled: true,
			UserConsentRead: true, UserConsent: "none",
			TrustedRootInventoryRead: false, MonitorConnected: &monitorConnected,
		},
	}

	checks := postActivationChecks(&StatusCmd{}, snapshot)

	for _, check := range checks {
		assert.NotEqual(t, checkIDTrustedRoots, check.ID)
	}
}

func TestCIRAConnectionStates(t *testing.T) {
	tests := []struct {
		name   string
		state  string
		status checkState
	}{
		{name: "connected", state: "connected", status: checkPass},
		{name: "connecting", state: "connecting", status: checkWarn},
		{name: "not connected", state: "not connected", status: checkFail},
		{name: "unknown", state: "unknown", status: checkUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			check := ciraConnectionCheck(&amt.RemoteAccessStatus{RemoteStatus: test.state})
			assert.Equal(t, test.status, check.Status)
			assert.NotContains(t, check.Message, "disconnected")
		})
	}
}

func TestVPNConnectionModeIsRecognized(t *testing.T) {
	check := connectionModeCheck(&amt.RemoteAccessStatus{NetworkStatus: "vpn"})

	assert.Equal(t, checkPass, check.Status)
	assert.Equal(t, "AMT Connection Mode: VPN", check.Message)

	verdict := EvaluateVerdict([]Check{{ID: checkIDWSMAN, Status: checkPass}, check})
	assert.Equal(t, resultReady, verdict.Result)
	assert.True(t, verdict.ReadyForManagement)
}

func TestPostActivationVerdictIgnoresOptionalUnknownsAndKeepsWarningsReady(t *testing.T) {
	verdict := EvaluateVerdict([]Check{
		{ID: checkIDWSMAN, Status: checkPass},
		{ID: checkIDDirectHost, Status: checkNotEvaluated},
		{ID: checkIDMonitor, Status: checkNotEvaluated},
		{ID: checkIDTrustedRoots, Status: checkWarn},
	})

	assert.Equal(t, resultReady, verdict.Result)
	assert.True(t, verdict.ReadyForManagement)
	assert.False(t, verdict.ReadyToProvision)
}

func TestPostActivationVerdictRequiresWSMAN(t *testing.T) {
	verdict := EvaluateVerdict([]Check{{ID: checkIDWSMAN, Status: checkUnavailable}})

	assert.Equal(t, resultUnknown, verdict.Result)
	assert.False(t, verdict.ReadyForManagement)
}

func TestUnauthorizedWSMANStopsPostActivationReads(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	wsman := mock.NewMockWSMANer(ctrl)
	wsman.EXPECT().GetGeneralSettings().Return(general.Response{}, &localamt.WSMANHTTPStatusError{
		StatusCode: http.StatusUnauthorized,
		Cause:      errors.New("unauthorized"),
	})
	expectActivatedStatusAMT(amtCommand)
	amtCommand.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "direct (LAN)",
	}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{
		HECIAvailable: true, ControlMode: commands.ControlModeCCM, WSMan: wsman,
	}}
	result := cmd.evaluate(&commands.Context{AMTCommand: amtCommand})
	assert.Nil(t, cmd.WSMan)

	var wsmanCheck Check

	for _, check := range result.Checks {
		if check.ID == checkIDWSMAN {
			wsmanCheck = check

			break
		}
	}

	assert.Equal(t, checkUnavailable, wsmanCheck.Status)
	assert.Contains(t, wsmanCheck.Message, "HTTP 401")
}

func TestUnauthorizedMPSReadClearsWSMANAndStopsDependentReads(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	wsman := mock.NewMockWSMANer(ctrl)
	wsman.EXPECT().GetGeneralSettings().Return(general.Response{}, nil)
	wsman.EXPECT().GetMPSSAP().Return(nil, &localamt.WSMANHTTPStatusError{
		StatusCode: http.StatusUnauthorized,
		Cause:      errors.New("unauthorized"),
	})
	expectActivatedStatusAMT(amtCommand)
	amtCommand.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "outside enterprise (CIRA)", RemoteStatus: "connecting",
	}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{
		HECIAvailable: true, ControlMode: commands.ControlModeCCM, WSMan: wsman,
	}}
	result := cmd.evaluate(&commands.Context{AMTCommand: amtCommand})

	assert.Nil(t, cmd.WSMan)
	assert.Contains(t, result.Checks, Check{ID: checkIDWSMAN, Name: checkNameWSMAN, Status: checkUnavailable, Message: "AMT rejected WSMAN credentials (HTTP 401)"})
}

func TestDirectServerTLSSkipsCIRAAndRootInventoryReads(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	wsman := mock.NewMockWSMANer(ctrl)
	wsman.EXPECT().GetGeneralSettings().Return(general.Response{}, nil)
	wsman.EXPECT().GetKVMRedirectionSAP().Return(cimkvm.Response{Body: cimkvm.Body{
		GetResponse: cimkvm.KVMRedirectionSAP{EnabledState: cimkvm.EnabledStateEnabled},
	}}, nil)
	wsman.EXPECT().GetRedirectionService().Return(redirection.Response{Body: redirection.Body{
		GetAndPutResponse: redirection.RedirectionResponse{EnabledState: redirection.IDERAndSOLAreEnabled, ListenerEnabled: true},
	}}, nil)
	wsman.EXPECT().GetIpsOptInService().Return(ipsoptin.Response{Body: ipsoptin.Body{
		GetAndPutResponse: ipsoptin.OptInServiceResponse{OptInRequired: uint32(ipsoptin.OptInRequiredNone)},
	}}, nil)
	wsman.EXPECT().EnumerateTLSSettingData().Return(amttls.Response{}, nil)
	wsman.EXPECT().PullTLSSettingData("").Return(amttls.Response{
		Body: amttls.Body{PullResponse: amttls.PullResponse{SettingDataItems: []amttls.SettingDataResponse{{
			InstanceID: "AMT 802.3 TLS Settings", Enabled: true,
		}}}},
	}, nil)
	expectActivatedStatusAMT(amtCommand)
	amtCommand.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "direct (LAN)", RemoteStatus: "connected",
	}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{
		HECIAvailable: true, ControlMode: commands.ControlModeCCM, WSMan: wsman,
	}}
	result := cmd.evaluate(&commands.Context{AMTCommand: amtCommand})

	assert.Equal(t, "Server", result.TLSMode)
	assert.NotContains(t, result.Checks, Check{ID: checkIDCIRA})

	for _, check := range result.Checks {
		assert.NotEqual(t, checkIDTrustedRoots, check.ID)
	}
}

func TestDirectHostReachabilityWithoutHostIsNotEvaluated(t *testing.T) {
	check := directHostReachabilityCheck("", "Server")

	assert.Equal(t, checkNotEvaluated, check.Status)
	assert.Contains(t, check.Message, "--host <console-address>")
}

func TestDirectHostEndpointUsesSchemeDefaultsAndKeepsExplicitPort(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		tlsMode string
		want    string
		wantErr bool
	}{
		{name: "HTTPS defaults to 443", host: "https://console.example.com", tlsMode: "Server", want: "console.example.com:443"},
		{name: "HTTP defaults to 80", host: "http://console.example.com/path", tlsMode: "Mutual", want: "console.example.com:80"},
		{name: "explicit URL port is preserved", host: "https://console.example.com:8443/path", tlsMode: "Server", want: "console.example.com:8443"},
		{name: "bare host uses AMT TLS port", host: "console.example.com", tlsMode: "Server", want: "console.example.com:16993"},
		{name: "unsupported scheme rejected", host: "ftp://console.example.com", tlsMode: "Server", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint, err := directHostEndpoint(test.host, test.tlsMode)
			if test.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.want, endpoint)
		})
	}
}

func expectActivatedStatusAMT(amtCommand *mock.MockInterface) {
	amtCommand.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("16.1.25", nil)
	amtCommand.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("16392", nil)
	amtCommand.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x82), nil)
	amtCommand.EXPECT().GetDNSSuffix().Return("", nil)
	amtCommand.EXPECT().GetOSDNSSuffix().Return("", nil)
	amtCommand.EXPECT().GetProvisioningState().Return(2, nil)
}

func TestProfileSpecificDNSAndNetworkChecks(t *testing.T) {
	assert.Equal(t, checkFail, dnsCheck("", "", true, true, true).Status)
	assert.Equal(t, checkFail, dnsCheck(".", ".", true, true, true).Status)
	assert.Equal(t, checkWarn, dnsCheck("", "", true, true, false).Status)
	assert.Equal(t, checkUnavailable, dnsCheck("", "", false, true, true).Status)

	hostSuffixFallback := dnsCheck(".", "host.example.com.", true, true, true)
	assert.Equal(t, checkWarn, hostSuffixFallback.Status)
	assert.Contains(t, hostSuffixFallback.Message, "host DNS suffix (host.example.com) can be used")
	assert.Equal(t, checkPass, dnsCheck("corp.example.com.", "corp.example.com", true, true, true).Status)

	assert.Equal(t, checkUnavailable, networkCheck(&commands.InfoResult{}, false, false).Status)
	assert.Equal(t, checkUnavailable, networkCheck(&commands.InfoResult{}, true, false).Status)

	noLinks := &commands.InfoResult{
		WiredAdapter:    &amt.InterfaceSettings{LinkStatus: "down"},
		WirelessAdapter: &amt.InterfaceSettings{LinkStatus: "down"},
	}
	assert.Equal(t, checkFail, networkCheck(noLinks, true, false).Status)
	assert.Equal(t, checkWarn, networkCheck(noLinks, false, true).Status)

	wirelessLink := &commands.InfoResult{
		WiredAdapter:    &amt.InterfaceSettings{LinkStatus: "down"},
		WirelessAdapter: &amt.InterfaceSettings{LinkStatus: "up"},
	}
	assert.Equal(t, checkFail, networkCheck(wirelessLink, true, false).Status)
	assert.Equal(t, checkUnavailable, networkCheck(&commands.InfoResult{WirelessAdapter: wirelessLink.WirelessAdapter}, true, false).Status)
	assert.Equal(t, checkPass, networkCheck(wirelessLink, false, true).Status)
}

func TestPostActivationRequiresAnAMTNetworkLink(t *testing.T) {
	noLinks := &commands.InfoResult{
		WiredAdapter:    &amt.InterfaceSettings{LinkStatus: "down"},
		WirelessAdapter: &amt.InterfaceSettings{LinkStatus: "down"},
	}
	check := postActivationNetworkCheck(noLinks)
	assert.Equal(t, checkFail, check.Status)
	assert.Contains(t, check.Message, "remote management")
	verdict := EvaluateVerdict([]Check{{ID: checkIDWSMAN, Status: checkPass}, check})
	assert.Equal(t, resultNotReady, verdict.Result)
	assert.False(t, verdict.ReadyForManagement)

	wiredUp := &commands.InfoResult{WiredAdapter: &amt.InterfaceSettings{LinkStatus: "up"}}
	assert.Equal(t, checkPass, postActivationNetworkCheck(wiredUp).Status)
	assert.Equal(t, checkUnavailable, postActivationNetworkCheck(&commands.InfoResult{}).Status)
}

func TestInfoSnapshotPreservesDNSQueryFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	amtCommand.EXPECT().GetDNSSuffix().Return("", errors.New("HECI query failed"))
	amtCommand.EXPECT().GetOSDNSSuffix().Return("", nil)

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 0, HECIAvailable: true}}
	snapshot := collectInfoSnapshot(cmd, &commands.Context{AMTCommand: amtCommand}, &commands.AmtInfoCmd{DNS: true})

	assert.False(t, snapshot.AMTDNSSuffixRead)
	assert.True(t, snapshot.OSDNSSuffixRead)
	check := dnsCheck(snapshot.Info.DNSSuffix, snapshot.Info.DNSSuffixOS, snapshot.AMTDNSSuffixRead, snapshot.OSDNSSuffixRead, true)
	assert.Equal(t, checkUnavailable, check.Status)
}

func TestDisabledAMTOperationalStateDoesNotBlockActivation(t *testing.T) {
	check, available := operationalStateCheck("disabled")
	verdict := EvaluateVerdict([]Check{check})

	assert.True(t, available)
	assert.Equal(t, checkWarn, check.Status)
	assert.Contains(t, check.Message, "local activation will attempt to enable it")
	assert.Equal(t, resultConditional, verdict.Result)
	assert.True(t, verdict.ReadyToProvision)
}

func TestMissingOperationalStateIsInformational(t *testing.T) {
	check, available := operationalStateCheck("")
	verdict := EvaluateVerdict([]Check{{ID: checkIDMEI, Status: checkPass}})

	assert.False(t, available)
	assert.Empty(t, check.ID)
	assert.Equal(t, resultReady, verdict.Result)
	assert.True(t, verdict.ReadyToProvision)

	var output bytes.Buffer

	result := report{AMTOperationalState: ""}
	require.NoError(t, renderText(&output, result))
	assert.Contains(t, output.String(), "Operational state: Not reported")
}

func TestRunUnprivilegedJSONReportsUnknown(t *testing.T) {
	oldElevated := statusIsElevated
	statusIsElevated = func() bool { return false }

	t.Cleanup(func() { statusIsElevated = oldElevated })

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: -1}}
	ctx := &commands.Context{AMTCommand: mock.NewMockInterface(gomock.NewController(t)), JsonOutput: true}

	var output bytes.Buffer

	err := run(&output, cmd, ctx)

	var customErr utils.CustomError
	require.ErrorAs(t, err, &customErr)
	assert.Equal(t, utils.GenericFailure.Code, customErr.Code)

	var parsed jsonOutput
	require.NoError(t, json.Unmarshal(output.Bytes(), &parsed))
	assert.Equal(t, resultUnknown, parsed.Evaluation.OverallResult)
	assert.False(t, parsed.Evaluation.ReadyToProvision)
	assert.Equal(t, "AMT status unknown (run as administrator)", parsed.Evaluation.OverallStatus)
}

func TestRunUnprivilegedTextReportsSameUnknownVerdict(t *testing.T) {
	oldElevated := statusIsElevated
	statusIsElevated = func() bool { return false }

	t.Cleanup(func() { statusIsElevated = oldElevated })

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: -1}}
	ctx := &commands.Context{AMTCommand: mock.NewMockInterface(gomock.NewController(t))}

	var output bytes.Buffer

	err := run(&output, cmd, ctx)

	var customErr utils.CustomError
	require.ErrorAs(t, err, &customErr)
	assert.Equal(t, utils.GenericFailure.Code, customErr.Code)
	assert.Contains(t, output.String(), "AMT status unknown (run as administrator)")
}

func TestEvaluateActivatedDeviceIsNotReadyOrHealthy(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	wsman := mock.NewMockWSMANer(ctrl)
	expectStatusWSMAN(wsman)
	expectActivatedStatusAMT(amtCommand)
	amtCommand.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{HECIAvailable: true, ControlMode: commands.ControlModeACM, WSMan: wsman}}
	result := cmd.evaluate(&commands.Context{AMTCommand: amtCommand})

	assert.Equal(t, "admin control mode", result.DetectedState)
	assert.Equal(t, checkSetPost, result.SelectedCheckSet)
	assert.Equal(t, resultUnknown, result.Verdict.Result)
	assert.False(t, result.Verdict.ReadyToProvision)
	assert.Contains(t, result.Verdict.Status, "unknown")
	assert.Equal(t, "supported, link up", result.WiredAdapterStatus)
	assert.Equal(t, "not supported", result.WirelessAdapterStatus)
}

func TestActivatedCCMTextShowsAMTLinkStatus(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	wsman := mock.NewMockWSMANer(ctrl)
	expectStatusWSMAN(wsman)
	expectActivatedStatusAMT(amtCommand)
	amtCommand.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{
		LinkStatus: "up", MACAddress: "48:21:0b:50:d8:c9",
	}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{
		LinkStatus: "down", MACAddress: "00:00:00:00:00:00",
	}, nil)

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{
		HECIAvailable: true, ControlMode: commands.ControlModeCCM, WSMan: wsman,
	}}
	result := cmd.evaluate(&commands.Context{AMTCommand: amtCommand})

	var output bytes.Buffer
	require.NoError(t, renderText(&output, result))
	assert.Contains(t, output.String(), "Detected state: Client Control Mode")
	assert.Contains(t, output.String(), "Selected checks: post-activation")
	assert.Contains(t, output.String(), "supported, link up")
	assert.Contains(t, output.String(), "not supported")
	assert.Contains(t, output.String(), "AMT-reported network status: Unavailable")
	assert.Contains(t, output.String(), "Remote access connection: Unavailable")
	assert.Contains(t, output.String(), "TLS mode: Unavailable (WSMAN data unavailable)")
	assert.Equal(t, resultUnknown, result.Verdict.Result)
}

func TestPreActivationChecksUseInfoServiceSnapshot(t *testing.T) {
	oldElevated := statusIsElevated
	oldDetectLMS := statusDetectLMS
	oldGetLMSVersion := statusGetLMSVersion
	statusIsElevated = func() bool { return true }
	statusDetectLMS = func(bool) bool { return true }
	statusGetLMSVersion = func() string { return "2406.0.0.0" }

	t.Cleanup(func() {
		statusIsElevated = oldElevated
		statusDetectLMS = oldDetectLMS
		statusGetLMSVersion = oldGetLMSVersion
	})

	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	amtCommand.EXPECT().GetVersionDataFromME("AMT", gomock.Any()).Return("16.1.0.0", nil)
	amtCommand.EXPECT().GetVersionDataFromME("Sku", gomock.Any()).Return("8", nil)
	amtCommand.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0x82), nil)
	amtCommand.EXPECT().GetDNSSuffix().Return("corp.example.com", nil)
	amtCommand.EXPECT().GetOSDNSSuffix().Return("CORP.EXAMPLE.COM", nil)
	amtCommand.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "outside enterprise (CIRA)", RemoteStatus: "connecting", RemoteTrigger: "provisioning",
	}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{ControlMode: 0, HECIAvailable: true}}
	result := cmd.evaluate(&commands.Context{AMTCommand: amtCommand})

	assert.Equal(t, "pre_provisioning", result.DetectedState)
	assert.Equal(t, resultReady, result.Verdict.Result)
	assert.True(t, result.Verdict.ReadyToProvision)
	assert.NotEmpty(t, result.AMTVersion)
	assert.Equal(t, "corp.example.com", result.AMTDNSSuffix)
	assert.Equal(t, "CORP.EXAMPLE.COM", result.OSDNSSuffix)
	assert.Equal(t, "connecting", result.RemoteAccess.RemoteStatus)
	assert.Contains(t, result.Checks, Check{ID: checkIDActivation, Name: checkNameActivation, Status: checkPass, Message: "AMT is in pre-provisioning mode"})
}

func TestStatusUsesSharedCIRAAndTLSSnapshot(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	wsman := mock.NewMockWSMANer(ctrl)
	wsman.EXPECT().GetGeneralSettings().Return(general.Response{}, nil)
	wsman.EXPECT().GetKVMRedirectionSAP().Return(cimkvm.Response{Body: cimkvm.Body{
		GetResponse: cimkvm.KVMRedirectionSAP{EnabledState: cimkvm.EnabledStateEnabled},
	}}, nil)
	wsman.EXPECT().GetRedirectionService().Return(redirection.Response{Body: redirection.Body{
		GetAndPutResponse: redirection.RedirectionResponse{EnabledState: redirection.IDERAndSOLAreEnabled, ListenerEnabled: true},
	}}, nil)
	wsman.EXPECT().GetIpsOptInService().Return(ipsoptin.Response{Body: ipsoptin.Body{
		GetAndPutResponse: ipsoptin.OptInServiceResponse{OptInRequired: uint32(ipsoptin.OptInRequiredNone)},
	}}, nil)
	wsman.EXPECT().GetMPSSAP().Return(nil, nil)
	wsman.EXPECT().GetRemoteAccessPolicies().Return(nil, nil)
	wsman.EXPECT().GetPublicKeyCerts().Return(nil, nil)
	wsman.EXPECT().EnumerateTLSSettingData().Return(amttls.Response{}, nil)
	wsman.EXPECT().PullTLSSettingData("").Return(amttls.Response{
		Body: amttls.Body{PullResponse: amttls.PullResponse{SettingDataItems: []amttls.SettingDataResponse{{
			InstanceID: "AMT 802.3 TLS Settings", Enabled: true, MutualAuthentication: true,
		}}}},
	}, nil)
	expectActivatedStatusAMT(amtCommand)
	amtCommand.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{
		NetworkStatus: "outside enterprise (CIRA)", RemoteStatus: "connecting", RemoteTrigger: "provisioning",
	}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(false).Return(amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"}, nil)
	amtCommand.EXPECT().GetLANInterfaceSettings(true).Return(amt.InterfaceSettings{LinkStatus: "down"}, nil)

	cmd := &StatusCmd{AMTBaseCmd: commands.AMTBaseCmd{
		HECIAvailable: true, ControlMode: commands.ControlModeCCM, WSMan: wsman,
	}}
	result := cmd.evaluate(&commands.Context{AMTCommand: amtCommand})

	assert.Equal(t, "outside enterprise (CIRA)", result.RemoteAccess.NetworkStatus)
	assert.Equal(t, "connecting", result.RemoteAccess.RemoteStatus)
	assert.Equal(t, "Mutual", result.TLSMode)
	assert.Contains(t, result.Checks, Check{ID: checkIDTLS, Name: checkNameTLS, Status: checkPass, Message: "TLS mode: Mutual"})
	assert.Contains(t, result.Checks, Check{ID: checkIDRedirection, Name: checkNameRedirection, Status: checkPass, Message: "redirection listener=true enabledState=32771"})
	assert.Equalf(t, resultNotReady, result.Verdict.Result, "checks: %+v", result.Checks)

	var text bytes.Buffer
	require.NoError(t, renderText(&text, result))
	assert.Contains(t, text.String(), "AMT-reported network status: outside enterprise (CIRA)")
	assert.Contains(t, text.String(), "Remote access connection: connecting")
	assert.Contains(t, text.String(), "Remote access trigger: provisioning")
	assert.Contains(t, text.String(), "TLS mode: Mutual")

	var machine bytes.Buffer
	require.NoError(t, renderJSON(&machine, &commands.Context{}, result))

	var parsed jsonOutput
	require.NoError(t, json.Unmarshal(machine.Bytes(), &parsed))
	assert.Equal(t, "outside enterprise (CIRA)", parsed.Evaluation.RemoteAccess.NetworkStatus)
	assert.Equal(t, "Mutual", parsed.Evaluation.TLSMode)
	assert.Equal(t, resultNotReady, parsed.Evaluation.OverallResult)
}

func TestReadyPostActivationReportRendersManagementReadiness(t *testing.T) {
	result := report{
		DetectedState:    "client control mode",
		SelectedCheckSet: checkSetPost,
		Host:             "console.example.com",
		Checks: []Check{
			{ID: checkIDWSMAN, Status: checkPass, Message: "Local WSMAN session available"},
			{ID: checkIDDirectHost, Status: checkNotEvaluated, Message: "No host probe requested"},
		},
	}
	result.Verdict = EvaluateVerdict(result.Checks)

	var text bytes.Buffer
	require.NoError(t, renderText(&text, result))
	assert.Contains(t, text.String(), "Device is fully configured and ready for remote management")
	assert.Contains(t, text.String(), "→ No action required.")

	var machine bytes.Buffer
	require.NoError(t, renderJSON(&machine, &commands.Context{}, result))

	var parsed jsonOutput
	require.NoError(t, json.Unmarshal(machine.Bytes(), &parsed))
	assert.Equal(t, resultReady, parsed.Evaluation.OverallResult)
	assert.True(t, parsed.Evaluation.ReadyForManagement)
	assert.Equal(t, "console.example.com", parsed.Evaluation.Host)
}

func TestTextAndJSONUseSameVerdict(t *testing.T) {
	result := report{
		DetectedState:    "pre_provisioning",
		SelectedCheckSet: checkSetPre,
		Checks:           []Check{{ID: checkIDMEI, Name: checkNameMEI, Status: checkPass, Message: "MEI/HECI driver is responding"}},
	}
	result.Verdict = EvaluateVerdict(result.Checks)

	var text bytes.Buffer
	require.NoError(t, renderText(&text, result))

	var machine bytes.Buffer
	require.NoError(t, renderJSON(&machine, &commands.Context{}, result))

	var output jsonOutput
	require.NoError(t, json.Unmarshal(machine.Bytes(), &output))
	assert.Equal(t, result.Verdict.Result, output.Evaluation.OverallResult)
	assert.Equal(t, result.Verdict.Status, output.Evaluation.OverallStatus)
	assert.Contains(t, text.String(), "  AMT Health Check")
	assert.Contains(t, text.String(), "Detected state: Pre-provisioning")
	assert.Contains(t, text.String(), "Selected checks: pre-activation")
	assert.Contains(t, text.String(), "Passed")
	assert.Contains(t, text.String(), "✓ MEI/HECI driver is responding")
	assert.Contains(t, text.String(), result.Verdict.Status)
	assert.Contains(t, text.String(), "SKU Information")
	assert.Contains(t, text.String(), "Processor: Not detected")
	assert.Equal(t, len(result.Checks), output.Evaluation.TotalChecks)
}

func TestConditionalDNSRecommendationAllowsSelectedActivationMode(t *testing.T) {
	tests := []struct {
		name               string
		selectedCheckSet   string
		wantRecommendation string
	}{
		{
			name:               "no profile selected",
			selectedCheckSet:   checkSetPre,
			wantRecommendation: "→ Proceed with ACM or CCM activation; verify the DNS suffix difference is compatible with the selected provisioning profile.",
		},
		{
			name:               "ACM selected",
			selectedCheckSet:   checkSetPreACM,
			wantRecommendation: "→ Proceed with ACM activation; verify the DNS suffix difference is compatible with the selected provisioning profile.",
		},
		{
			name:               "CCM selected",
			selectedCheckSet:   checkSetPreCCM,
			wantRecommendation: "→ Proceed with CCM activation; verify the DNS suffix difference is compatible with the selected provisioning profile.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := report{
				SelectedCheckSet: tt.selectedCheckSet,
				Checks: []Check{{
					ID: checkIDDNS, Name: checkNameDNS, Status: checkWarn,
					Message: "AMT DNS suffix (vprodemo.com) differs from host DNS suffix (iind.intel.com). Confirm this matches your provisioning setup",
				}},
			}
			result.Verdict = EvaluateVerdict(result.Checks)

			var output bytes.Buffer
			require.NoError(t, renderText(&output, result))

			assert.Equal(t, resultConditional, result.Verdict.Result)
			assert.True(t, result.Verdict.ReadyToProvision)
			assert.Contains(t, result.Verdict.Status, "DNS suffixes differ")
			assert.Contains(t, output.String(), tt.wantRecommendation)
			assert.NotContains(t, output.String(), "ACM is blocked")
		})
	}
}

func TestActivationProfileReadinessPredictsACMAndCCM(t *testing.T) {
	oldDetectLMS := statusDetectLMS
	statusDetectLMS = func(bool) bool { return true }

	t.Cleanup(func() { statusDetectLMS = oldDetectLMS })

	snapshot := &commands.InfoSnapshot{Info: &commands.InfoResult{
		ControlMode:      "not activated",
		Features:         "AMT Pro Corporate",
		AMT:              "16.1.25",
		SKU:              "16392",
		DNSSuffix:        "vprodemo.com",
		DNSSuffixOS:      "iind.intel.com",
		OperationalState: "enabled",
		WiredAdapter:     &amt.InterfaceSettings{LinkStatus: "up", MACAddress: "00:11:22:33:44:55"},
		WirelessAdapter:  &amt.InterfaceSettings{LinkStatus: "down"},
	}, AMTDNSSuffixRead: true, OSDNSSuffixRead: true}
	profiles := evaluateActivationProfiles(snapshot, initialChecks(true, true, nil, ""))

	require.Len(t, profiles, 2)
	assert.Equal(t, "ACM", profiles[0].Profile)
	assert.Equal(t, resultConditional, profiles[0].Result)
	assert.True(t, profiles[0].ReadyToProvision)
	assert.Equal(t, "CCM", profiles[1].Profile)
	assert.Equal(t, resultConditional, profiles[1].Result)
	assert.True(t, profiles[1].ReadyToProvision)

	var output bytes.Buffer
	require.NoError(t, renderJSON(&output, &commands.Context{}, report{
		ActivationProfiles: profiles,
		Verdict:            Verdict{Result: resultConditional, Status: "Device is conditionally ready", ReadyToProvision: true},
	}))

	var parsed jsonOutput
	require.NoError(t, json.Unmarshal(output.Bytes(), &parsed))
	assert.Equal(t, "ACM", parsed.Evaluation.ActivationProfiles[0].Profile)
	assert.Equal(t, "CCM", parsed.Evaluation.ActivationProfiles[1].Profile)
}

func TestActivationProfileReadinessAllowsCCMWhenACMPrerequisitesFail(t *testing.T) {
	oldDetectLMS := statusDetectLMS
	statusDetectLMS = func(bool) bool { return true }

	t.Cleanup(func() { statusDetectLMS = oldDetectLMS })

	snapshot := &commands.InfoSnapshot{Info: &commands.InfoResult{
		ControlMode:      "not activated",
		Features:         "AMT Pro Corporate",
		AMT:              "16.1.25",
		SKU:              "16392",
		OperationalState: "enabled",
		WiredAdapter:     &amt.InterfaceSettings{LinkStatus: "down", MACAddress: "00:11:22:33:44:55"},
		WirelessAdapter:  &amt.InterfaceSettings{LinkStatus: "down"},
	}, AMTDNSSuffixRead: true, OSDNSSuffixRead: true}
	profiles := evaluateActivationProfiles(snapshot, initialChecks(true, true, nil, ""))

	require.Len(t, profiles, 2)
	assert.Equal(t, "ACM", profiles[0].Profile)
	assert.Equal(t, resultNotReady, profiles[0].Result)
	assert.False(t, profiles[0].ReadyToProvision)
	assert.Equal(t, "CCM", profiles[1].Profile)
	assert.Equal(t, resultConditional, profiles[1].Result)
	assert.True(t, profiles[1].ReadyToProvision)
}

func TestTextRecommendationShowsCCMAlternativeWhenACMIsBlocked(t *testing.T) {
	result := report{
		DetectedState:    "pre_provisioning",
		SelectedCheckSet: checkSetPreACM,
		Verdict: Verdict{
			Result: resultNotReady,
			Status: "Device is not ready for the selected activation profile",
		},
		ActivationProfiles: []activationProfileReadiness{
			{Profile: "ACM", Result: resultNotReady},
			{Profile: "CCM", Result: resultConditional, ReadyToProvision: true},
		},
	}

	var output bytes.Buffer
	require.NoError(t, renderText(&output, result))

	assert.Contains(t, output.String(), "ACM: Not ready")
	assert.Contains(t, output.String(), "CCM: Conditionally ready")
	assert.Contains(t, output.String(), "CCM can proceed; ACM has failed prerequisites listed above.")
}
