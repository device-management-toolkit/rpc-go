/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package status

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

var (
	statusDetectLMS           = utils.DetectLMS
	statusGetMEIDriverVersion = utils.GetMEIDriverVersion
	statusGetLMSVersion       = utils.GetLMSVersion
)

const (
	stateEnabled                   = "enabled"
	stateDisabled                  = "disabled"
	directHostProbeTimeout         = 3 * time.Second
	maxLegacyOperationalStateMajor = 11
)

func initialChecks(elevated, heciAvailable bool, heciInitErr error, meiDriverVersion string) []Check {
	adminStatus := checkPass
	adminMessage := "Running as administrator/root"

	if !elevated {
		adminStatus = checkUnavailable
		adminMessage = "Administrator/root access is required to query AMT"
	}

	heciStatus := checkPass
	heciMessage := "MEI/HECI driver is responding"

	if !heciAvailable {
		heciStatus = checkUnavailable
		heciMessage = "MEI/HECI availability could not be determined"

		if elevated && errors.Is(heciInitErr, heci.ErrDeviceNotFound) {
			heciStatus = checkFail
			heciMessage = "MEI/HECI device was not found"
		} else if elevated && errors.Is(heciInitErr, heci.ErrUnsupportedDevice) {
			heciStatus = checkFail
			heciMessage = "MEI/HECI device does not support AMT/PTHI"
		}
	} else if version := strings.TrimSpace(meiDriverVersion); version != "" {
		heciMessage += " (version " + version + ")"
	}

	return []Check{
		{ID: checkIDAdmin, Name: checkNameAdmin, Status: adminStatus, Message: adminMessage},
		{ID: checkIDMEI, Name: checkNameMEI, Status: heciStatus, Message: heciMessage},
	}
}

func collectPreActivationChecks(cmd *StatusCmd, ctx *commands.Context) ([]Check, *commands.InfoSnapshot) {
	infoCmd := &commands.AmtInfoCmd{
		Ver: true, Sku: true, Mode: true, DNS: true, Lan: true, Ras: true, OpState: true,
	}
	snapshot := collectInfoSnapshot(cmd, ctx, infoCmd)

	return preActivationChecks(cmd, snapshot), snapshot
}

func collectPostActivationChecks(cmd *StatusCmd, ctx *commands.Context) ([]Check, *commands.InfoSnapshot) {
	infoCmd := &commands.AmtInfoCmd{
		Ver: true, Sku: true, Mode: true, ProvState: true, DNS: true, Lan: true, Ras: true, OpState: true,
	}
	snapshot := collectInfoSnapshot(cmd, ctx, infoCmd)

	return postActivationChecks(cmd, snapshot), snapshot
}

func postActivationChecks(cmd *StatusCmd, snapshot *commands.InfoSnapshot) []Check {
	if snapshot == nil || snapshot.Info == nil {
		return []Check{{ID: "amt_snapshot", Name: checkNameAMTInfo, Status: checkUnavailable, Message: "AMT information could not be collected"}}
	}

	info := snapshot.Info

	checks := []Check{
		{ID: checkIDActivation, Name: checkNameActivation, Status: checkPass, Message: "AMT activated state: " + info.ControlMode},
		platformCheck(info.Features, info.AMT, info.SKU),
		versionCheck(info.AMT),
		dnsCheck(info.DNSSuffix, info.DNSSuffixOS, snapshot.AMTDNSSuffixRead, snapshot.OSDNSSuffixRead, false),
		postActivationNetworkCheck(info),
		lmsCheck(cmd.LocalTLSEnforced),
		provisioningStatePostCheck(info.ProvisioningState, snapshot.ProvisioningStateRead),
		wsmanSessionCheck(snapshot.PostActivation),
		connectionModeCheck(info.RAS),
	}
	if shouldCheckOperationalState(info.AMT, snapshot.OperationalStateSupported) {
		checks = append(checks, operationalStatePostCheck(info.OperationalState, snapshot.OperationalStateRead))
	}

	if requestedMode, ok := requestedPostActivationModeCheck(cmd, info.ControlMode); ok {
		checks = append(checks, requestedMode)
	}

	if info.RAS != nil && strings.EqualFold(strings.TrimSpace(info.RAS.NetworkStatus), "outside enterprise (CIRA)") {
		checks = append(checks, ciraConfigurationCheck(snapshot.PostActivation), ciraConnectionCheck(info.RAS))
	}

	var post *commands.PostActivationSnapshot
	if snapshot != nil {
		post = snapshot.PostActivation
	}

	checks = append(checks,
		redirectionCheck(post),
		solCheck(post),
		userConsentCheck(post),
		tlsModeCheck(snapshot.TLSMode, post),
		monitorCheck(post.MonitorConnected),
	)
	if !strings.Contains(info.Features, deviceTypeISM) {
		checks = append(checks, kvmCheck(post))
	}

	if tlsRequiresTrustedRoots(snapshot.TLSMode) {
		checks = append(checks, trustedRootsCheck(snapshot.TLSMode, post))
	}

	if info.RAS != nil && strings.EqualFold(strings.TrimSpace(info.RAS.NetworkStatus), "direct (LAN)") {
		checks = append(checks, directHostReachabilityCheck(cmd.Host, snapshot.TLSMode))
	}

	return checks
}

func requestedPostActivationModeCheck(cmd *StatusCmd, actualMode string) (Check, bool) {
	if cmd.ACM {
		requestedMode := utils.InterpretControlMode(commands.ControlModeACM)
		if strings.EqualFold(strings.TrimSpace(actualMode), requestedMode) {
			return Check{ID: checkIDRequestedMode, Name: checkNameRequestedMode, Status: checkPass, Message: "AMT control mode matches requested ACM"}, true
		}

		return Check{ID: checkIDRequestedMode, Name: checkNameRequestedMode, Status: checkFail, Message: "AMT is in " + displayDetectedState(actualMode) + "; --acm was requested"}, true
	}

	if cmd.CCM {
		requestedMode := utils.InterpretControlMode(commands.ControlModeCCM)
		if strings.EqualFold(strings.TrimSpace(actualMode), requestedMode) {
			return Check{ID: checkIDRequestedMode, Name: checkNameRequestedMode, Status: checkPass, Message: "AMT control mode matches requested CCM"}, true
		}

		return Check{ID: checkIDRequestedMode, Name: checkNameRequestedMode, Status: checkFail, Message: "AMT is in " + displayDetectedState(actualMode) + "; --ccm was requested"}, true
	}

	return Check{}, false
}

func operationalStatePostCheck(state string, read bool) Check {
	if !read {
		return Check{ID: checkIDOperationalState, Name: checkNameOperationalState, Status: checkUnavailable, Message: "AMT operational state could not be read"}
	}

	switch strings.ToLower(strings.TrimSpace(state)) {
	case stateEnabled:
		return Check{ID: checkIDOperationalState, Name: checkNameOperationalState, Status: checkPass, Message: "AMT operational state is enabled"}
	case stateDisabled:
		return Check{ID: checkIDOperationalState, Name: checkNameOperationalState, Status: checkFail, Message: "AMT operational state is disabled"}
	default:
		return Check{ID: checkIDOperationalState, Name: checkNameOperationalState, Status: checkUnavailable, Message: "AMT operational state is unknown"}
	}
}

func provisioningStatePostCheck(state string, read bool) Check {
	if !read {
		return Check{ID: checkIDProvisioningState, Name: checkNameProvisioningState, Status: checkUnavailable, Message: "AMT provisioning state could not be read"}
	}

	switch strings.ToLower(strings.TrimSpace(state)) {
	case "post-provisioning":
		return Check{ID: checkIDProvisioningState, Name: checkNameProvisioningState, Status: checkPass, Message: "AMT provisioning is complete"}
	case "pre-provisioning", "in provisioning":
		return Check{ID: checkIDProvisioningState, Name: checkNameProvisioningState, Status: checkFail, Message: "AMT provisioning is incomplete: " + state}
	default:
		return Check{ID: checkIDProvisioningState, Name: checkNameProvisioningState, Status: checkUnavailable, Message: "AMT provisioning state is unknown: " + state}
	}
}

func supportsOperationalState(amtVersion string) bool {
	parts := strings.SplitN(strings.TrimSpace(amtVersion), ".", 2)
	major, err := strconv.Atoi(parts[0])

	return err == nil && major > maxLegacyOperationalStateMajor
}

func shouldCheckOperationalState(amtVersion string, supported *bool) bool {
	if !supportsOperationalState(amtVersion) {
		return false
	}

	return supported == nil || *supported
}

func wsmanSessionCheck(snapshot *commands.PostActivationSnapshot) Check {
	if snapshot == nil {
		return Check{ID: checkIDWSMAN, Name: checkNameWSMAN, Status: checkUnavailable, Message: "Local WSMAN session could not be evaluated"}
	}

	switch snapshot.WSMANStatus {
	case commands.WSMANStatusAvailable:
		return Check{ID: checkIDWSMAN, Name: checkNameWSMAN, Status: checkPass, Message: "Local WSMAN session available"}
	case commands.WSMANStatusUnauthorized:
		return Check{ID: checkIDWSMAN, Name: checkNameWSMAN, Status: checkUnavailable, Message: snapshot.WSMANMessage}
	case commands.WSMANStatusUnavailable:
		message := snapshot.WSMANMessage
		if message == "" {
			message = "Local WSMAN session is unavailable"
		}

		return Check{ID: checkIDWSMAN, Name: checkNameWSMAN, Status: checkUnavailable, Message: message}
	default:
		message := snapshot.WSMANMessage
		if message == "" {
			message = "Local WSMAN session is unavailable"
		}

		return Check{ID: checkIDWSMAN, Name: checkNameWSMAN, Status: checkUnavailable, Message: message}
	}
}

func connectionModeCheck(status *amt.RemoteAccessStatus) Check {
	if status == nil {
		return Check{ID: checkIDConnectionMode, Name: checkNameConnectionMode, Status: checkUnavailable, Message: "AMT connection mode could not be read"}
	}

	switch strings.ToLower(strings.TrimSpace(status.NetworkStatus)) {
	case "direct (lan)":
		return Check{ID: checkIDConnectionMode, Name: checkNameConnectionMode, Status: checkPass, Message: "AMT Connection Mode: Direct"}
	case "outside enterprise (cira)":
		return Check{ID: checkIDConnectionMode, Name: checkNameConnectionMode, Status: checkPass, Message: "AMT Connection Mode: CIRA"}
	case "vpn":
		return Check{ID: checkIDConnectionMode, Name: checkNameConnectionMode, Status: checkPass, Message: "AMT Connection Mode: VPN"}
	default:
		return Check{ID: checkIDConnectionMode, Name: checkNameConnectionMode, Status: checkUnavailable, Message: "AMT connection mode is unknown: " + status.NetworkStatus}
	}
}

func ciraConfigurationCheck(snapshot *commands.PostActivationSnapshot) Check {
	if snapshot == nil || !snapshot.CIRAConfigRead {
		return Check{ID: checkIDCIRA, Name: checkNameCIRA, Status: checkUnavailable, Message: "CIRA configuration could not be read"}
	}

	if !snapshot.CIRAConfigured {
		return Check{ID: checkIDCIRA, Name: checkNameCIRA, Status: checkFail, Message: "CIRA mode is active but no MPS and remote-access policy are configured"}
	}

	return Check{ID: checkIDCIRA, Name: checkNameCIRA, Status: checkPass, Message: "CIRA MPS and remote-access policy are configured"}
}

func ciraConnectionCheck(status *amt.RemoteAccessStatus) Check {
	if status == nil {
		return Check{ID: checkIDCIRAState, Name: checkNameCIRAState, Status: checkUnavailable, Message: "CIRA connection state could not be read"}
	}

	switch strings.ToLower(strings.TrimSpace(status.RemoteStatus)) {
	case "connected":
		return Check{ID: checkIDCIRAState, Name: checkNameCIRAState, Status: checkPass, Message: "CIRA connection is connected"}
	case "connecting":
		return Check{ID: checkIDCIRAState, Name: checkNameCIRAState, Status: checkWarn, Message: "CIRA connection is connecting"}
	case "not connected":
		return Check{ID: checkIDCIRAState, Name: checkNameCIRAState, Status: checkFail, Message: "CIRA connection is not connected"}
	default:
		return Check{ID: checkIDCIRAState, Name: checkNameCIRAState, Status: checkUnavailable, Message: "CIRA connection state is unknown: " + status.RemoteStatus}
	}
}

func redirectionCheck(snapshot *commands.PostActivationSnapshot) Check {
	if snapshot == nil || !snapshot.RedirectionRead {
		return Check{ID: checkIDRedirection, Name: checkNameRedirection, Status: checkUnavailable, Message: "Redirection service settings could not be read"}
	}

	state, err := strconv.Atoi(snapshot.RedirectionState)

	message := fmt.Sprintf("redirection listener=%t enabledState=%s", snapshot.RedirectionListenerEnabled, snapshot.RedirectionState)
	if err != nil {
		return Check{ID: checkIDRedirection, Name: checkNameRedirection, Status: checkUnavailable, Message: message + "; enabled state is unknown"}
	}

	switch state {
	case 32769, 32770, 32771:
		if snapshot.RedirectionListenerEnabled {
			return Check{ID: checkIDRedirection, Name: checkNameRedirection, Status: checkPass, Message: message}
		}

		return Check{ID: checkIDRedirection, Name: checkNameRedirection, Status: checkFail, Message: message + "; listener is disabled"}
	case 32768:
		return Check{ID: checkIDRedirection, Name: checkNameRedirection, Status: checkWarn, Message: message + "; SOL and IDER are disabled"}
	default:
		return Check{ID: checkIDRedirection, Name: checkNameRedirection, Status: checkUnavailable, Message: message + "; enabled state is unknown"}
	}
}

func solCheck(snapshot *commands.PostActivationSnapshot) Check {
	if snapshot == nil || !snapshot.RedirectionRead {
		return Check{ID: checkIDSOL, Name: checkNameSOL, Status: checkUnavailable, Message: "SOL redirection state could not be read"}
	}

	state, err := strconv.Atoi(snapshot.RedirectionState)
	if err != nil {
		return Check{ID: checkIDSOL, Name: checkNameSOL, Status: checkUnavailable, Message: "SOL redirection state is unknown"}
	}

	switch state {
	case int(redirection.SOLIsEnabledAndIDERIsDisabled), int(redirection.IDERAndSOLAreEnabled):
		if !snapshot.RedirectionListenerEnabled {
			return Check{ID: checkIDSOL, Name: checkNameSOL, Status: checkFail, Message: "SOL is configured but the redirection listener is disabled"}
		}

		return Check{ID: checkIDSOL, Name: checkNameSOL, Status: checkPass, Message: "SOL is enabled"}
	case int(redirection.IDERAndSOLAreDisabled), int(redirection.IDERIsEnabledAndSOLIsDisabled):
		return Check{ID: checkIDSOL, Name: checkNameSOL, Status: checkWarn, Message: "SOL is disabled"}
	default:
		return Check{ID: checkIDSOL, Name: checkNameSOL, Status: checkUnavailable, Message: "SOL redirection state is unknown"}
	}
}

func userConsentCheck(snapshot *commands.PostActivationSnapshot) Check {
	if snapshot == nil || !snapshot.UserConsentRead {
		return Check{ID: checkIDUserConsent, Name: checkNameUserConsent, Status: checkUnavailable, Message: "KVM user-consent setting could not be read"}
	}

	consent := strings.TrimSpace(snapshot.UserConsent)
	if strings.EqualFold(consent, "none") {
		return Check{ID: checkIDUserConsent, Name: checkNameUserConsent, Status: checkPass, Message: "KVM user consent: none"}
	}

	if consent == "" {
		return Check{ID: checkIDUserConsent, Name: checkNameUserConsent, Status: checkUnavailable, Message: "KVM user-consent setting is unknown"}
	}

	return Check{ID: checkIDUserConsent, Name: checkNameUserConsent, Status: checkWarn, Message: "KVM user consent is required: " + consent}
}

func tlsModeCheck(mode string, snapshot *commands.PostActivationSnapshot) Check {
	if snapshot == nil || !snapshot.TLSModeRead || strings.TrimSpace(mode) == "" || strings.EqualFold(mode, "unknown") {
		return Check{ID: checkIDTLS, Name: checkNameTLS, Status: checkUnavailable, Message: "AMT TLS mode could not be read"}
	}

	if strings.EqualFold(mode, "none") {
		return Check{ID: checkIDTLS, Name: checkNameTLS, Status: checkWarn, Message: "AMT TLS is disabled"}
	}

	return Check{ID: checkIDTLS, Name: checkNameTLS, Status: checkPass, Message: "TLS mode: " + mode}
}

func trustedRootsCheck(mode string, snapshot *commands.PostActivationSnapshot) Check {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "mutual", "mutualandnontls":
		if snapshot == nil || !snapshot.TrustedRootInventoryRead {
			return Check{ID: checkIDTrustedRoots, Name: checkNameTrustedRoots, Status: checkUnavailable, Message: "Trusted root certificate inventory could not be read for mutual TLS"}
		}

		if snapshot.TrustedRootCount == 0 {
			return Check{ID: checkIDTrustedRoots, Name: checkNameTrustedRoots, Status: checkFail, Message: "Mutual TLS is enabled but no trusted root certificates are installed"}
		}

		return Check{ID: checkIDTrustedRoots, Name: checkNameTrustedRoots, Status: checkPass, Message: fmt.Sprintf("%d trusted root certificate(s) installed", snapshot.TrustedRootCount)}
	case "server", "serverandnontls", "none":
		return Check{ID: checkIDTrustedRoots, Name: checkNameTrustedRoots, Status: checkNotEvaluated, Message: "Trusted root certificates are not required for TLS mode " + mode}
	default:
		return Check{ID: checkIDTrustedRoots, Name: checkNameTrustedRoots, Status: checkUnavailable, Message: "Trusted root requirements could not be determined without a TLS mode"}
	}
}

func tlsRequiresTrustedRoots(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "mutual", "mutualandnontls":
		return true
	default:
		return false
	}
}

func kvmCheck(snapshot *commands.PostActivationSnapshot) Check {
	if snapshot == nil || !snapshot.KVMRead {
		return Check{ID: checkIDKVM, Name: checkNameKVM, Status: checkUnavailable, Message: "KVM Redirection SAP state could not be read"}
	}

	switch strings.ToLower(snapshot.KVMState) {
	case stateEnabled:
		return Check{ID: checkIDKVM, Name: checkNameKVM, Status: checkPass, Message: "KVM is enabled"}
	case stateDisabled:
		return Check{ID: checkIDKVM, Name: checkNameKVM, Status: checkWarn, Message: "KVM is disabled"}
	default:
		return Check{ID: checkIDKVM, Name: checkNameKVM, Status: checkUnavailable, Message: "KVM Redirection SAP returned an unknown state"}
	}
}

func monitorCheck(connected *bool) Check {
	if connected == nil {
		return Check{ID: checkIDMonitor, Name: checkNameMonitor, Status: checkNotEvaluated, Message: "Monitor connection could not be detected on this platform"}
	}

	if *connected {
		return Check{ID: checkIDMonitor, Name: checkNameMonitor, Status: checkPass, Message: "Monitor connected"}
	}

	return Check{ID: checkIDMonitor, Name: checkNameMonitor, Status: checkWarn, Message: "No monitor detected"}
}

func directHostReachabilityCheck(host, tlsMode string) Check {
	host = strings.TrimSpace(host)
	if host == "" {
		return Check{ID: checkIDDirectHost, Name: checkNameDirectHost, Status: checkNotEvaluated, Message: "Direct mode: use --host <console-address> to probe console reachability"}
	}

	endpoint, err := directHostEndpoint(host, tlsMode)
	if err != nil {
		return Check{ID: checkIDDirectHost, Name: checkNameDirectHost, Status: checkWarn, Message: "Invalid console address: " + host}
	}

	dialer := net.Dialer{Timeout: directHostProbeTimeout}

	connection, err := dialer.DialContext(context.Background(), "tcp", endpoint)
	if err != nil {
		return Check{ID: checkIDDirectHost, Name: checkNameDirectHost, Status: checkWarn, Message: "Console endpoint is not reachable: " + err.Error()}
	}

	_ = connection.Close()

	return Check{ID: checkIDDirectHost, Name: checkNameDirectHost, Status: checkPass, Message: "Console endpoint is reachable at " + endpoint}
}

func directHostEndpoint(host, tlsMode string) (string, error) {
	port := "16992"
	if strings.EqualFold(tlsMode, "Server") || strings.EqualFold(tlsMode, "Mutual") {
		port = "16993"
	}

	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil || parsed.Host == "" {
			return "", fmt.Errorf("invalid console URL")
		}

		switch strings.ToLower(parsed.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("unsupported console URL scheme %q", parsed.Scheme)
		}

		host = parsed.Host
	}

	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}

	host = strings.Trim(host, "[]")
	if host == "" {
		return "", fmt.Errorf("console host is empty")
	}

	return net.JoinHostPort(host, port), nil
}

func collectInfoSnapshot(cmd *StatusCmd, ctx *commands.Context, infoCmd *commands.AmtInfoCmd) *commands.InfoSnapshot {
	service := commands.NewInfoService(
		ctx.AMTCommand,
		commands.WithPassword(ctx.AMTPassword),
		commands.WithLocalTLSEnforced(cmd.LocalTLSEnforced),
		commands.WithSkipAMTCertCheck(ctx.SkipAMTCertCheck),
		commands.WithWSMANClient(cmd.GetWSManClient()),
		commands.WithHECIAvailable(cmd.HECIAvailable),
		commands.WithCachedControlMode(cmd.ControlMode),
	)
	defer service.CloseOwnedWSMANClient()

	snapshot := service.GetInfoSnapshot(infoCmd, true)
	if snapshot.PostActivation != nil && snapshot.PostActivation.WSMANStatus == commands.WSMANStatusUnauthorized {
		cmd.WSMan = nil
	}

	return snapshot
}

func preActivationChecks(cmd *StatusCmd, snapshot *commands.InfoSnapshot) []Check {
	if snapshot == nil || snapshot.Info == nil {
		return []Check{{ID: "amt_snapshot", Name: checkNameAMTInfo, Status: checkUnavailable, Message: "AMT information could not be collected"}}
	}

	info := snapshot.Info
	checks := make([]Check, 0, 7)
	checks = append(checks, activationCheck(info.ControlMode))

	checks = append(checks, platformCheck(info.Features, info.AMT, info.SKU))
	if operationalCheck, available := operationalStateCheck(info.OperationalState); available {
		checks = append(checks, operationalCheck)
	}

	checks = append(checks, versionCheck(info.AMT))
	checks = append(checks, dnsCheck(info.DNSSuffix, info.DNSSuffixOS, snapshot.AMTDNSSuffixRead, snapshot.OSDNSSuffixRead, cmd.ACM))
	checks = append(checks, networkCheck(info, cmd.ACM, cmd.CCM))
	checks = append(checks, lmsCheck(cmd.LocalTLSEnforced))

	return checks
}

func evaluateActivationProfiles(snapshot *commands.InfoSnapshot, checks []Check) []activationProfileReadiness {
	if snapshot == nil || snapshot.Info == nil || snapshot.Info.ControlMode != utils.InterpretControlMode(0) {
		return nil
	}

	commonChecks := make([]Check, 0, len(checks))
	for _, check := range checks {
		if check.ID != checkIDDNS && check.ID != checkIDNetwork {
			commonChecks = append(commonChecks, check)
		}
	}

	profiles := []struct {
		name     string
		acm, ccm bool
	}{
		{name: "ACM", acm: true},
		{name: "CCM", ccm: true},
	}
	readiness := make([]activationProfileReadiness, 0, len(profiles))

	for _, profile := range profiles {
		profileChecks := append([]Check(nil), commonChecks...)
		profileChecks = append(profileChecks,
			dnsCheck(snapshot.Info.DNSSuffix, snapshot.Info.DNSSuffixOS, snapshot.AMTDNSSuffixRead, snapshot.OSDNSSuffixRead, profile.acm),
			networkCheck(snapshot.Info, profile.acm, profile.ccm),
		)
		verdict := EvaluateVerdict(profileChecks)
		readiness = append(readiness, activationProfileReadiness{
			Profile:          profile.name,
			Result:           verdict.Result,
			Status:           verdict.Status,
			ReadyToProvision: verdict.ReadyToProvision,
		})
	}

	return readiness
}

func populateSnapshot(result *report, snapshot *commands.InfoSnapshot) {
	if result == nil || snapshot == nil || snapshot.Info == nil {
		return
	}

	result.DeviceType = snapshot.Info.Features
	result.AMTVersion = snapshot.Info.AMT
	result.AMTDNSSuffix = snapshot.Info.DNSSuffix
	result.OSDNSSuffix = snapshot.Info.DNSSuffixOS
	result.AMTOperationalState = snapshot.Info.OperationalState
	result.RemoteAccess = snapshot.Info.RAS
	result.TLSMode = snapshot.TLSMode
	result.WiredAdapterStatus = adapterStatus(snapshot.Info.WiredAdapter)
	result.WirelessAdapterStatus = adapterStatus(snapshot.Info.WirelessAdapter)
}

func activationCheck(controlMode string) Check {
	switch strings.ToLower(strings.TrimSpace(controlMode)) {
	case "", "unknown control mode":
		return Check{ID: checkIDActivation, Name: checkNameActivation, Status: checkUnavailable, Message: "AMT control mode could not be read"}
	case utils.InterpretControlMode(1), utils.InterpretControlMode(2):
		return Check{ID: checkIDActivation, Name: checkNameActivation, Status: checkAlreadyActive, Message: "AMT is already activated: " + controlMode}
	case utils.InterpretControlMode(0):
		return Check{ID: checkIDActivation, Name: checkNameActivation, Status: checkPass, Message: "AMT is in pre-provisioning mode"}
	default:
		return Check{ID: checkIDActivation, Name: checkNameActivation, Status: checkUnavailable, Message: "AMT control mode is unsupported or unknown: " + controlMode}
	}
}

func platformCheck(features, version, sku string) Check {
	if features == "" && version != "" && sku != "" {
		features = utils.DecodeAMTFeatures(version, sku)
	}

	switch {
	case features == "" || strings.Contains(features, "Invalid") || strings.Contains(features, "Unknown"):
		return Check{ID: checkIDPlatform, Name: checkNamePlatform, Status: checkWarn, Message: "Platform type could not be determined"}
	case strings.Contains(features, "AMT Pro"):
		return Check{ID: checkIDPlatform, Name: checkNamePlatform, Status: checkPass, Message: "Platform type: vPro"}
	case strings.Contains(features, deviceTypeISM):
		return Check{ID: checkIDPlatform, Name: checkNamePlatform, Status: checkPass, Message: "Platform type: ISM"}
	default:
		return Check{ID: checkIDPlatform, Name: checkNamePlatform, Status: checkFail, Message: "Platform is not AMT-capable: " + features}
	}
}

func operationalStateCheck(operationalState string) (Check, bool) {
	switch strings.ToLower(strings.TrimSpace(operationalState)) {
	case "enabled":
		return Check{ID: checkIDOperationalState, Name: checkNameOperationalState, Status: checkPass, Message: "AMT operational state is enabled"}, true
	case "disabled":
		return Check{ID: checkIDOperationalState, Name: checkNameOperationalState, Status: checkWarn, Message: "AMT operational state is disabled; local activation will attempt to enable it"}, true
	default:
		return Check{}, false
	}
}

func versionCheck(amtVersion string) Check {
	parts := strings.Split(strings.TrimSpace(amtVersion), ".")
	if len(parts) == 0 || parts[0] == "" {
		return Check{ID: checkIDVersion, Name: checkNameVersion, Status: checkWarn, Message: "Could not read AMT version"}
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return Check{ID: checkIDVersion, Name: checkNameVersion, Status: checkWarn, Message: "Could not parse AMT version " + amtVersion}
	}

	if major >= minSupportedAMTMajor && major <= maxSupportedAMTMajor {
		return Check{ID: checkIDVersion, Name: checkNameVersion, Status: checkPass, Message: "AMT version " + amtVersion + " is supported"}
	}

	return Check{ID: checkIDVersion, Name: checkNameVersion, Status: checkWarn, Message: "AMT version " + amtVersion + " is outside the supported range"}
}

func dnsCheck(amtSuffix, osSuffix string, amtSuffixRead, osSuffixRead, acm bool) Check {
	amtSuffix = strings.TrimSuffix(strings.TrimSpace(amtSuffix), ".")
	osSuffix = strings.TrimSuffix(strings.TrimSpace(osSuffix), ".")

	if amtSuffix == "" {
		if osSuffix != "" {
			return Check{ID: checkIDDNS, Name: checkNameDNS, Status: checkWarn, Message: "AMT DNS suffix is not configured; host DNS suffix (" + osSuffix + ") can be used for remote activation"}
		}

		if !amtSuffixRead || !osSuffixRead {
			return Check{ID: checkIDDNS, Name: checkNameDNS, Status: checkUnavailable, Message: "AMT and host DNS suffixes could not be determined"}
		}

		if acm {
			return Check{ID: checkIDDNS, Name: checkNameDNS, Status: checkFail, Message: "AMT or host DNS suffix is required for ACM activation"}
		}

		return Check{ID: checkIDDNS, Name: checkNameDNS, Status: checkWarn, Message: "AMT DNS suffix is not configured; CCM can still proceed"}
	}

	if !osSuffixRead {
		return Check{ID: checkIDDNS, Name: checkNameDNS, Status: checkUnavailable, Message: "Host DNS suffix could not be read; suffix compatibility could not be checked"}
	}

	if osSuffix == "" || strings.EqualFold(amtSuffix, osSuffix) {
		return Check{ID: checkIDDNS, Name: checkNameDNS, Status: checkPass, Message: "AMT DNS suffix configured: " + amtSuffix}
	}

	return Check{ID: checkIDDNS, Name: checkNameDNS, Status: checkWarn, Message: "AMT DNS suffix (" + amtSuffix + ") differs from host DNS suffix (" + osSuffix + "). Confirm this matches your provisioning setup"}
}

func networkCheck(info *commands.InfoResult, acm, ccm bool) Check {
	if info == nil || (info.WiredAdapter == nil && info.WirelessAdapter == nil) {
		return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkUnavailable, Message: "AMT network settings were not collected"}
	}

	if acm && info.WiredAdapter == nil {
		return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkUnavailable, Message: "AMT wired network settings could not be collected"}
	}

	wiredUp := info.WiredAdapter != nil && strings.EqualFold(info.WiredAdapter.LinkStatus, statusLinkUp)

	wirelessUp := info.WirelessAdapter != nil && strings.EqualFold(info.WirelessAdapter.LinkStatus, statusLinkUp)

	if acm {
		if wiredUp {
			return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkPass, Message: "Wired AMT link is up for ACM activation"}
		}

		return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkFail, Message: "ACM activation requires a wired AMT link"}
	}

	if wiredUp || (ccm && wirelessUp) {
		return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkPass, Message: "AMT network link is available"}
	}

	if wirelessUp {
		return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkWarn, Message: "Wireless link is up; ACM activation requires wired link"}
	}

	return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkWarn, Message: "No AMT network link detected; CCM can still proceed locally"}
}

func postActivationNetworkCheck(info *commands.InfoResult) Check {
	if info == nil || (info.WiredAdapter == nil && info.WirelessAdapter == nil) {
		return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkUnavailable, Message: "AMT network settings were not collected"}
	}

	wiredUp := info.WiredAdapter != nil && strings.EqualFold(info.WiredAdapter.LinkStatus, statusLinkUp)
	wirelessUp := info.WirelessAdapter != nil && strings.EqualFold(info.WirelessAdapter.LinkStatus, statusLinkUp)

	if wiredUp || wirelessUp {
		return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkPass, Message: "AMT network link is available for remote management"}
	}

	if info.WiredAdapter != nil && info.WirelessAdapter != nil {
		return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkFail, Message: "No AMT network link is available for remote management"}
	}

	return Check{ID: checkIDNetwork, Name: checkNameNetwork, Status: checkUnavailable, Message: "Not all AMT network links could be checked"}
}

func lmsCheck(localTLSEnforced bool) Check {
	if statusDetectLMS(localTLSEnforced) {
		message := "Local Manageability Service is listening"
		if version := strings.TrimSpace(statusGetLMSVersion()); version != "" {
			message += " (version " + version + ")"
		}

		return Check{ID: checkIDLMS, Name: checkNameLMS, Status: checkPass, Message: message}
	}

	return Check{ID: checkIDLMS, Name: checkNameLMS, Status: checkWarn, Message: "Local Manageability Service is not reachable"}
}

func adapterStatus(adapter *amt.InterfaceSettings) string {
	if adapter == nil {
		return "not detected"
	}

	supported := adapter.IsEnabled || (adapter.MACAddress != "" && adapter.MACAddress != "00:00:00:00:00:00")
	if !supported {
		return "not supported"
	}

	linkStatus := "down"
	if strings.EqualFold(adapter.LinkStatus, statusLinkUp) {
		linkStatus = statusLinkUp
	}

	return "supported, link " + linkStatus
}
