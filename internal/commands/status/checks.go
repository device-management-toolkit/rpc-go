/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package status

import (
	"errors"
	"strconv"
	"strings"

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

	return service.GetInfoSnapshot(infoCmd, true)
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
