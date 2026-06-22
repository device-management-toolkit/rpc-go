/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	wsmantls "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// Defaults for the status (health) checks.
const (
	statusDialTimeout = 2 * time.Second
	defaultHostPort   = "443"
	// linkStatusUp is the AMT-reported value compared against; the display uses
	// the connected/disconnected wording below.
	linkStatusUp     = "up"
	linkConnected    = "connected"
	linkDisconnected = "disconnected"
	meVersionTimeout = 10 * time.Second
)

// verdictBoxStyle is the shared rounded-box style for the readiness summary;
// renderVerdict applies the per-state color. Colors reuse the amtinfo palette
// (green 78, red 168, header blue 39).
var verdictBoxStyle = lipgloss.NewStyle().
	Bold(true).
	Border(lipgloss.RoundedBorder()).
	Padding(0, 1)

// lmsDependentFeatures are example capabilities that rely on the Local
// Manageability Service and are unavailable when it is not running.
var lmsDependentFeatures = []string{
	"All soft power actions (e.g. power on, sleep, reset)",
	"UEFI Profile Sharing Sync",
	"OS WiFi Network Sync",
	"Clock/Time Sync",
}

// statusDialTCP attempts a TCP connection and reports whether it succeeded.
// It is a package var so tests can stub network access.
var statusDialTCP = func(address string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return err
	}

	return conn.Close()
}

// statusDetectMonitorConnected is a package var so tests can stub OS monitor access.
var statusDetectMonitorConnected = utils.DetectMonitorConnected

// checkState models the outcome of a single readiness check.
type checkState int

const (
	checkPass checkState = iota // requirement satisfied (green)
	checkWarn                   // not satisfied, but not fatal on its own (yellow)
	checkFail                   // requirement not satisfied (red)
	checkSkip                   // not applicable / not evaluated (dim)
)

// Repeated string literals extracted as constants for goconst compliance.
const (
	checkSetPostActivation = "post_activation"
	checkSetPreActivation  = "pre_activation"
	skipMEIRequired        = "unavailable (MEI driver required)"
	skipWSMANRequired      = "unavailable (WSMAN client required)"
	tlsModeNone            = "None"
	tlsModeUnknown         = "Unknown"
	checkStateActivated    = "activated"
	checkStateUnknown      = "unknown"
	checkStatusPass        = "pass"
)

// symbol renders the colored status glyph for the check state.
func (s checkState) symbol() string {
	switch s {
	case checkPass:
		return infoGreenStyle.Render("✓")
	case checkWarn:
		return infoYellowStyle.Render("○")
	case checkFail:
		return infoRedStyle.Render("✗")
	case checkSkip:
		return infoDimStyle.Render("–")
	default:
		return infoDimStyle.Render("–")
	}
}

// healthCheck is a single labeled readiness check with an optional detail.
type healthCheck struct {
	label  string
	state  checkState
	detail string
}

// StatusResult is the machine-readable result of the status command.
type StatusResult struct {
	Command                string `json:"command,omitempty"`
	MEIDriverPresent       bool   `json:"meiDriverPresent"`
	AMTEnabledInBIOS       *bool  `json:"amtEnabledInBIOS,omitempty"`
	ControlMode            string `json:"controlMode,omitempty"`
	SelectedCheckSet       string `json:"selectedCheckSet"`
	AlreadyActivated       bool   `json:"alreadyActivated"`
	DNSSuffixMatch         bool   `json:"dnsSuffixMatch,omitempty"`
	DeviceType             string `json:"deviceType,omitempty"`
	LMSInstalled           bool   `json:"lmsInstalled"`
	WiredSupported         bool   `json:"wiredSupported"`
	WirelessSupported      bool   `json:"wirelessSupported"`
	WiredLinkUp            bool   `json:"wiredLinkUp"`
	WirelessLinkUp         bool   `json:"wirelessLinkUp"`
	Host                   string `json:"host,omitempty"`
	HostReachable          *bool  `json:"hostReachable,omitempty"`
	ConnectionMode         string `json:"connectionMode,omitempty"`
	MPSHostname            string `json:"mpsHostname,omitempty"`
	MPSPort                int    `json:"mpsPort,omitempty"`
	CIRAConfigured         *bool  `json:"ciraConfigured,omitempty"`
	CIRAConnected          *bool  `json:"ciraConnected,omitempty"`
	CIRAPrerequisites      *bool  `json:"ciraPrerequisites,omitempty"`
	WSMANAvailable         *bool  `json:"wsmanAvailable,omitempty"`
	TLSMode                string `json:"tlsMode,omitempty"`
	TrustedRootCertCount   int    `json:"trustedRootCertCount,omitempty"`
	UserConsent            string `json:"userConsent,omitempty"`
	RemoteManageabilityUp  *bool  `json:"remoteManageabilityUp,omitempty"`
	OCRBIOSVerified        *bool  `json:"ocrBiosVerified,omitempty"`
	MonitorConnected       *bool  `json:"monitorConnected,omitempty"`
	KVMEnabled             *bool  `json:"kvmEnabled,omitempty"`
	PartialEvaluation      bool   `json:"partialEvaluation,omitempty"`
	PartialReason          string `json:"partialReason,omitempty"`
	ReadyToProvision       bool   `json:"readyToProvision"`
	ManageableInProduction bool   `json:"manageableInProduction"`
}

type statusJSONCheck struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type statusJSONOutput struct {
	StatusResult
	DetectedState    string            `json:"detected_state"`
	SelectedCheckSet string            `json:"selected_check_set"`
	OverallResult    string            `json:"overall_result"`
	Checks           []statusJSONCheck `json:"checks"`
}

type redirectionSnapshot struct {
	ok              bool
	enabledState    int
	listenerEnabled bool
}

// StatusCmd reports whether the local device is ready to be provisioned or,
// once activated, whether it is healthy for day-2 manageability.
type StatusCmd struct {
	AMTBaseCmd

	Host              string `help:"Host[:port] to test network reachability against (default port 443)" name:"host"`
	wsmanStatusDetail string `kong:"-"`
}

// RequiresAMTPassword indicates this command never needs an AMT password.
func (cmd *StatusCmd) RequiresAMTPassword() bool {
	return false
}

// BeforeApply lets AMTBaseCmd.AfterApply tolerate a missing MEI driver so the
// status command can report it as a failed check instead of aborting.
func (cmd *StatusCmd) BeforeApply() error {
	cmd.SkipWSMANSetup = true

	return nil
}

// Run executes the status command.
func (cmd *StatusCmd) Run(ctx *Context) error {
	log.Trace("Running status command")

	cmd.wsmanStatusDetail = ""

	result, checks := cmd.gather(ctx)

	if ctx.JsonOutput {
		if err := outputStatusJSON(os.Stdout, result, checks); err != nil {
			return err
		}
	} else {
		renderStatus(os.Stdout, result, checks)
	}

	// Signal to Execute() that elevation would unlock the AMT-dependent checks.
	// Skip on non-x86 architectures: AMT cannot exist there, so elevating would
	// not surface anything and prompting would be pointless.
	if !cmd.HECIAvailable && !utils.IsElevated() && amtCapableArch() {
		return utils.IncorrectPermissions
	}

	return nil
}

func (cmd *StatusCmd) preparePostActivationWSMAN(ctx *Context) {
	if cmd.WSMan != nil {
		return
	}

	if strings.TrimSpace(ctx.AMTPassword) == "" {
		cmd.wsmanStatusDetail = "AMT password not provided; WSMAN-only checks skipped"

		return
	}

	if err := cmd.EnsureWSMAN(ctx); err != nil {
		log.Debugf("status: WSMAN setup unavailable for post-activation checks: %v", err)

		cmd.wsmanStatusDetail = "could not initialize WSMAN client"
	}
}

// gather runs every readiness check and computes the overall verdict.
func (cmd *StatusCmd) gather(ctx *Context) (StatusResult, []healthCheck) {
	result := StatusResult{Command: "status"}

	mei := cmd.meiCheck(&result)
	controlMode := cmd.controlModeCheck(&result)

	if result.AlreadyActivated {
		cmd.preparePostActivationWSMAN(ctx)

		result.SelectedCheckSet = checkSetPostActivation

		_ = controlMode

		return cmd.gatherPostActivation(ctx, result, []healthCheck{mei})
	}

	result.SelectedCheckSet = checkSetPreActivation

	return cmd.gatherPreActivation(ctx, result, []healthCheck{mei, controlMode})
}

func (cmd *StatusCmd) gatherPreActivation(ctx *Context, result StatusResult, checks []healthCheck) (StatusResult, []healthCheck) {
	checks = append(checks[:1],
		cmd.amtEnabledInBIOSCheck(&result),
		checks[1],
		cmd.dnsSuffixCheck(ctx, &result),
		cmd.deviceTypeCheck(ctx, &result),
		cmd.lmsCheck(&result),
		cmd.linkCheck(ctx, false, &result),
		cmd.linkCheck(ctx, true, &result),
	)

	if hostCheck, ok := cmd.hostCheck(&result); ok {
		checks = append(checks, hostCheck)
	}

	// An already-activated device is not a provisioning candidate; the verdict
	// reports that instead. Otherwise it is ready when this is an AMT device in
	// pre-provisioning with at least one network link up. Two checks do not gate
	// provisioning: LMS (its absence only limits LMS-based features) and host
	// reachability (it gates remote manageability, surfaced in the verdict).
	networkUp := result.WiredLinkUp || result.WirelessLinkUp
	result.ReadyToProvision = !result.AlreadyActivated && result.MEIDriverPresent && networkUp

	return result, checks
}

func (cmd *StatusCmd) gatherPostActivation(ctx *Context, result StatusResult, checks []healthCheck) (StatusResult, []healthCheck) {
	activated := cmd.activatedStateCheck(&result)
	wsman := cmd.wsmanAccessCheck(&result)
	connection := cmd.connectionModeCheck(ctx, &result)
	tlsTrust := cmd.tlsTrustCheck(&result)
	redirection := cmd.readRedirectionSnapshot()
	featurePolicy := cmd.featurePolicyCheck(&result, redirection)
	remoteManageability := cmd.remoteManageabilityCheck(&result)
	kvm := cmd.kvmCheck(&result, redirection)

	checks = append(checks,
		activated,
		cmd.deviceTypeCheck(ctx, &result),
		cmd.lmsCheck(&result),
		wsman,
		connection,
		cmd.ciraConfigCheck(&result),
		cmd.ciraConnectionCheck(&result),
		cmd.ciraPrerequisitesCheck(&result),
		tlsTrust,
		featurePolicy,
		remoteManageability,
		cmd.ocrBIOSCheck(&result),
		cmd.monitorCheck(&result),
		kvm,
	)

	result.ManageableInProduction = result.MEIDriverPresent && result.AlreadyActivated
	if result.WSMANAvailable == nil || !*result.WSMANAvailable {
		result.PartialEvaluation = true
		result.PartialReason = wsman.detail
		result.ManageableInProduction = false

		return result, checks
	}

	if result.CIRAConfigured != nil && *result.CIRAConfigured && (result.CIRAConnected == nil || !*result.CIRAConnected) {
		result.ManageableInProduction = false
	}

	if tlsTrust.state != checkPass {
		result.ManageableInProduction = false
	}

	if featurePolicy.state != checkPass {
		result.ManageableInProduction = false
	}

	if result.KVMEnabled != nil && !*result.KVMEnabled {
		result.ManageableInProduction = false
	}

	return result, checks
}

func (cmd *StatusCmd) activatedStateCheck(result *StatusResult) healthCheck {
	const label = "AMT activated state"

	if !result.AlreadyActivated {
		return healthCheck{label, checkSkip, "device is not activated"}
	}

	detail := result.ControlMode
	if detail == "" {
		detail = checkStateActivated
	}

	return healthCheck{label, checkPass, detail + " active"}
}

func (cmd *StatusCmd) wsmanAccessCheck(result *StatusResult) healthCheck {
	const label = "Local WSMAN session"

	available := cmd.WSMan != nil
	result.WSMANAvailable = &available

	if available {
		return healthCheck{label, checkPass, "post-activation WSMAN checks available"}
	}

	if cmd.wsmanStatusDetail != "" {
		return healthCheck{label, checkWarn, cmd.wsmanStatusDetail}
	}

	return healthCheck{label, checkWarn, "WSMAN-based checks unavailable"}
}

// meiCheck reports whether the MEI/HECI driver is present (i.e. this is an AMT device).
func (cmd *StatusCmd) meiCheck(result *StatusResult) healthCheck {
	const label = "MEI driver present (AMT device)"

	result.MEIDriverPresent = cmd.HECIAvailable

	if cmd.HECIAvailable {
		return healthCheck{label, checkPass, "MEI/HECI driver detected"}
	}

	if !amtCapableArch() {
		return healthCheck{label, checkFail, runtime.GOARCH + " CPU does not support Intel AMT"}
	}

	if !utils.IsElevated() {
		return healthCheck{label, checkFail, "requires administrator privileges to verify"}
	}

	return healthCheck{label, checkFail, "MEI/HECI driver not detected"}
}

func (cmd *StatusCmd) amtEnabledInBIOSCheck(result *StatusResult) healthCheck {
	const label = "AMT enabled in BIOS"

	enabled := cmd.HECIAvailable
	result.AMTEnabledInBIOS = &enabled

	if enabled {
		return healthCheck{label, checkPass, "AMT/MEI interface accessible"}
	}

	if !amtCapableArch() {
		return healthCheck{label, checkFail, runtime.GOARCH + " CPU does not support Intel AMT"}
	}

	return healthCheck{label, checkFail, "AMT/MEI interface not accessible"}
}

// controlModeCheck reports the activation state. Pre-provisioning (control
// mode 0) is the green, ready-to-activate state; an already-activated device
// (CCM/ACM) is flagged so the verdict reports it rather than "ready".
func (cmd *StatusCmd) controlModeCheck(result *StatusResult) healthCheck {
	const label = "Control mode"

	if !cmd.HECIAvailable {
		return healthCheck{label, checkSkip, skipMEIRequired}
	}

	result.ControlMode = utils.InterpretControlMode(cmd.ControlMode)

	switch cmd.ControlMode {
	case ControlModeCCM, ControlModeACM:
		result.AlreadyActivated = true

		return healthCheck{label, checkWarn, "already activated (" + result.ControlMode + ")"}
	default:
		return healthCheck{label, checkPass, "pre-provisioning (ready to activate)"}
	}
}

// dnsSuffixCheck compares the AMT-configured DNS suffix with the OS DNS suffix.
// A mismatch prevents DNS-based provisioning from succeeding.
func (cmd *StatusCmd) dnsSuffixCheck(ctx *Context, result *StatusResult) healthCheck {
	const label = "DNS suffix (AMT vs OS)"

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		return healthCheck{label, checkSkip, skipMEIRequired}
	}

	amtSuffix, err := ctx.AMTCommand.GetDNSSuffix()
	if err != nil {
		return healthCheck{label, checkWarn, "could not read AMT DNS suffix"}
	}

	if amtSuffix == "" {
		return healthCheck{label, checkWarn, "AMT DNS suffix not configured"}
	}

	osSuffix, err := ctx.AMTCommand.GetOSDNSSuffix()
	if err != nil || osSuffix == "" {
		return healthCheck{label, checkWarn, "could not verify OS DNS suffix (AMT: " + amtSuffix + ")"}
	}

	if strings.EqualFold(amtSuffix, osSuffix) {
		result.DNSSuffixMatch = true

		return healthCheck{label, checkPass, amtSuffix}
	}

	return healthCheck{label, checkFail, "AMT=" + amtSuffix + " OS=" + osSuffix}
}

// deviceTypeCheck reports whether the device is a full AMT vPro or a limited
// Intel Standard Manageability (ISM) product. ISM lacks KVM, SOL, and other
// advanced provisioning capabilities.
func (cmd *StatusCmd) deviceTypeCheck(ctx *Context, result *StatusResult) healthCheck {
	const label = "AMT device type"

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		return healthCheck{label, checkSkip, skipMEIRequired}
	}

	sku, err := ctx.AMTCommand.GetVersionDataFromME("Sku", meVersionTimeout)
	if err != nil {
		return healthCheck{label, checkWarn, "could not read device SKU"}
	}

	ver, err := ctx.AMTCommand.GetVersionDataFromME("AMT", meVersionTimeout)
	if err != nil {
		return healthCheck{label, checkWarn, "could not read AMT version"}
	}

	features := utils.DecodeAMTFeatures(ver, sku)
	result.DeviceType = features

	switch {
	case strings.Contains(features, "AMT Pro"):
		return healthCheck{label, checkPass, "Intel vPro (" + features + ")"}
	case strings.Contains(features, "Intel Standard Manageability"):
		return healthCheck{label, checkWarn, "ISM device – limited manageability (" + features + ")"}
	default:
		return healthCheck{label, checkWarn, features}
	}
}

// lmsCheck reports whether the Local Manageability Service is listening locally.
// LMS serves the plain port (16992) and, on TLS-enforced devices, the TLS port
// (16993); either being open means LMS is present.
func (cmd *StatusCmd) lmsCheck(result *StatusResult) healthCheck {
	const label = "LMS (Local Manageability Service)"

	port, ok := lmsReachable()
	result.LMSInstalled = ok

	probed := utils.LMSAddress + ":" + utils.LMSPort + "/" + utils.LMSTLSPort + " (TLS)"

	if ok {
		return healthCheck{label, checkPass, "listening on " + net.JoinHostPort(utils.LMSAddress, port)}
	}

	return healthCheck{label, checkFail, "not reachable on " + probed}
}

// linkCheck reports the AMT-reported link status for the wired or wireless adapter.
// A down link is a warning (not a failure) since only one link needs to be up.
func (cmd *StatusCmd) linkCheck(ctx *Context, wireless bool, result *StatusResult) healthCheck {
	label := "Wired network link"
	if wireless {
		label = "Wireless network link"
	}

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		return healthCheck{label, checkSkip, skipMEIRequired}
	}

	settings, err := ctx.AMTCommand.GetLANInterfaceSettings(wireless)
	if err != nil {
		log.Debugf("failed to read LAN interface settings (wireless=%v): %v", wireless, err)

		return healthCheck{label, checkWarn, "could not read link status"}
	}

	supported := settings.IsEnabled || settings.LinkStatus != "" || settings.MACAddress != "" ||
		settings.IPAddress != "" || settings.OsIPAddress != ""
	if wireless {
		result.WirelessSupported = supported
	} else {
		result.WiredSupported = supported
	}

	if !strings.EqualFold(settings.LinkStatus, linkStatusUp) {
		if !supported {
			return healthCheck{label, checkWarn, "not detected or disabled"}
		}

		return healthCheck{label, checkWarn, linkDisconnected}
	}

	if wireless {
		result.WirelessLinkUp = true
	} else {
		result.WiredLinkUp = true
	}

	detail := linkConnected
	if settings.IPAddress != "" && settings.IPAddress != zeroIP {
		detail = linkConnected + " (" + settings.IPAddress + ")"
	}

	return healthCheck{label, checkPass, detail}
}

func (cmd *StatusCmd) connectionModeCheck(ctx *Context, result *StatusResult) healthCheck {
	const label = "Connection mode"

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		return healthCheck{label, checkSkip, skipMEIRequired}
	}

	status, err := ctx.AMTCommand.GetRemoteAccessConnectionStatus()
	if err != nil {
		return healthCheck{label, checkWarn, "could not read remote access status"}
	}

	mode := "direct-connect"
	if strings.Contains(strings.ToLower(status.NetworkStatus), "cira") {
		mode = "CIRA"
	}

	result.ConnectionMode = mode
	result.MPSHostname = status.MPSHostname
	result.MPSPort = status.MPSPort
	connected := strings.EqualFold(status.RemoteStatus, "connected")
	result.CIRAConnected = &connected

	detail := status.NetworkStatus

	if status.MPSHostname != "" {
		detail += " via " + status.MPSHostname
	}

	if status.RemoteStatus != "" {
		detail += " (" + status.RemoteStatus + ")"
	}

	return healthCheck{label, checkPass, strings.TrimSpace(detail)}
}

func (cmd *StatusCmd) tlsTrustCheck(result *StatusResult) healthCheck {
	const label = "TLS configuration / trust inventory"

	if cmd.WSMan == nil {
		return healthCheck{label, checkSkip, skipWSMANRequired}
	}

	enumerateRsp, err := cmd.WSMan.EnumerateTLSSettingData()
	if err != nil {
		return healthCheck{label, checkWarn, "could not enumerate TLS settings"}
	}

	pullRsp, err := cmd.WSMan.PullTLSSettingData(enumerateRsp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return healthCheck{label, checkWarn, "could not read TLS settings"}
	}

	mode := ""

	for _, item := range pullRsp.Body.PullResponse.SettingDataItems {
		if strings.HasSuffix(item.InstanceID, "AMT 802.3 TLS Settings") {
			mode = tlsModeLabel(item)

			break
		}
	}

	if mode == "" {
		return healthCheck{label, checkWarn, "remote TLS settings not found"}
	}

	result.TLSMode = mode

	publicKeyCerts, err := cmd.WSMan.GetPublicKeyCerts()
	if err != nil {
		return healthCheck{label, checkWarn, "TLS mode " + mode + ", certificate inventory unavailable"}
	}

	trustedRoots := 0

	for _, cert := range publicKeyCerts {
		if cert.TrustedRootCertificate {
			trustedRoots++
		}
	}

	result.TrustedRootCertCount = trustedRoots

	if mode == tlsModeNone {
		return healthCheck{label, checkWarn, "TLS disabled on management interface"}
	}

	if trustedRoots > 0 {
		return healthCheck{label, checkPass, fmt.Sprintf("mode %s, %d trusted root certificate(s) in inventory", mode, trustedRoots)}
	}

	return healthCheck{label, checkWarn, "mode " + mode + ", no trusted root certificates found in inventory"}
}

func (cmd *StatusCmd) readRedirectionSnapshot() redirectionSnapshot {
	if cmd.WSMan == nil {
		return redirectionSnapshot{}
	}

	response, err := cmd.WSMan.GetRedirectionService()
	if err != nil {
		return redirectionSnapshot{}
	}

	service := response.Body.GetAndPutResponse

	return redirectionSnapshot{
		ok:              true,
		enabledState:    int(service.EnabledState),
		listenerEnabled: service.ListenerEnabled,
	}
}

func (cmd *StatusCmd) featurePolicyCheck(result *StatusResult, redirection redirectionSnapshot) healthCheck {
	const label = "Redirection / consent baseline"

	if cmd.WSMan == nil {
		return healthCheck{label, checkSkip, skipWSMANRequired}
	}

	if !redirection.ok {
		return healthCheck{label, checkWarn, "could not read redirection policy"}
	}

	// enabledState==2 is the CIM standard "Enabled"; AMT also reports extended
	// values >=32768 (e.g. 32771) for session-active states. listenerEnabled is
	// the reliable signal that redirection will accept incoming connections.
	enabled := redirection.listenerEnabled && (redirection.enabledState == 2 || redirection.enabledState >= 32768)
	parts := []string{fmt.Sprintf("redirection listener=%t enabledState=%d", redirection.listenerEnabled, redirection.enabledState)}

	// Read user consent policy first to determine pass/warn state
	if cmd.ControlMode == ControlModeACM {
		optIn, optErr := cmd.WSMan.GetIpsOptInService()
		if optErr != nil {
			return healthCheck{label, checkWarn, "could not read user consent policy"}
		}

		result.UserConsent = formatUserConsent(optIn.Body.GetAndPutResponse.OptInRequired)
		parts = append(parts, "user consent="+result.UserConsent)
	} else {
		result.UserConsent = "all"

		parts = append(parts, "user consent=all (CCM default)")
	}

	// Pass if redirection is enabled.
	// In CCM, consent=all is expected and normal (user must approve at screen).
	// In ACM, if consent=all, that's also valid (though unattended would require consent=none).
	state := checkWarn
	if enabled {
		state = checkPass
	}

	return healthCheck{label, state, strings.Join(parts, ", ")}
}

func (cmd *StatusCmd) remoteManageabilityCheck(result *StatusResult) healthCheck {
	const label = "Management endpoint reachability"

	target := ""
	source := ""

	if strings.TrimSpace(cmd.Host) != "" {
		target = resolveHostTarget(cmd.Host)
		source = "user target"
	} else if strings.EqualFold(result.ConnectionMode, "CIRA") && strings.TrimSpace(result.MPSHostname) != "" {
		port := result.MPSPort
		if port == 0 {
			port = 443
		}

		target = net.JoinHostPort(result.MPSHostname, strconv.Itoa(port))

		source = "MPS"
	}

	if target == "" {
		return healthCheck{label, checkSkip, "no management endpoint available for local probe"}
	}

	reachable := statusDialTCP(target, statusDialTimeout) == nil
	result.RemoteManageabilityUp = &reachable

	if reachable {
		return healthCheck{label, checkPass, source + " reachable from device at " + target}
	}

	// If CIRA is already connected the device IS manageable via the ME tunnel;
	// the OS-level TCP probe failing is expected (MPS may only accept ME connections).
	if result.CIRAConnected != nil && *result.CIRAConnected {
		return healthCheck{label, checkPass, source + " reachable via active CIRA tunnel (OS probe blocked at " + target + ")"}
	}

	return healthCheck{label, checkWarn, source + " unreachable from device at " + target}
}

func (cmd *StatusCmd) ciraConfigCheck(result *StatusResult) healthCheck {
	const label = "CIRA configuration"

	if cmd.WSMan == nil {
		return healthCheck{label, checkSkip, skipWSMANRequired}
	}

	policies, err := cmd.WSMan.GetRemoteAccessPolicies()
	if err != nil {
		return healthCheck{label, checkWarn, "could not read remote access policies"}
	}

	mps, err := cmd.WSMan.GetMPSSAP()
	if err != nil {
		return healthCheck{label, checkWarn, "could not read MPS configuration"}
	}

	configured := len(policies) > 0 && len(mps) > 0
	result.CIRAConfigured = &configured

	if configured {
		return healthCheck{label, checkPass, fmt.Sprintf("%d policies, %d MPS entries", len(policies), len(mps))}
	}

	return healthCheck{label, checkWarn, "no CIRA policy/MPS mapping found"}
}

func (cmd *StatusCmd) ciraConnectionCheck(result *StatusResult) healthCheck {
	const label = "CIRA connected"

	if result.ConnectionMode != "CIRA" {
		return healthCheck{label, checkSkip, "device is in direct-connect mode"}
	}

	if result.CIRAConnected == nil {
		return healthCheck{label, checkSkip, "remote access status unavailable"}
	}

	if *result.CIRAConnected {
		return healthCheck{label, checkPass, "connected to MPS"}
	}

	return healthCheck{label, checkWarn, "not connected to MPS"}
}

func (cmd *StatusCmd) ciraPrerequisitesCheck(result *StatusResult) healthCheck {
	const label = "CIRA prerequisites"

	if cmd.WSMan == nil {
		return healthCheck{label, checkSkip, skipWSMANRequired}
	}

	settings, err := cmd.WSMan.GetEnvironmentDetectionSettings()
	if err != nil {
		return healthCheck{label, checkWarn, "could not read environment detection settings"}
	}

	configured := len(settings.DetectionStrings) > 0 || len(settings.DetectionIPv6LocalPrefixes) > 0
	result.CIRAPrerequisites = &configured

	if configured {
		return healthCheck{label, checkPass, "environment detection configured"}
	}

	return healthCheck{label, checkWarn, "environment detection not configured"}
}

func (cmd *StatusCmd) ocrBIOSCheck(result *StatusResult) healthCheck {
	const label = "OCR enabled in BIOS"

	result.OCRBIOSVerified = nil

	return healthCheck{label, checkSkip, "out of scope for current local checks"}
}

func (cmd *StatusCmd) monitorCheck(result *StatusResult) healthCheck {
	const label = "Monitor connected for KVM"

	connected := statusDetectMonitorConnected()
	result.MonitorConnected = connected

	if connected == nil {
		return healthCheck{label, checkSkip, "could not determine monitor state"}
	}

	if *connected {
		return healthCheck{label, checkPass, "monitor detected"}
	}

	return healthCheck{label, checkWarn, "no monitor detected"}
}

func (cmd *StatusCmd) kvmCheck(result *StatusResult, redirection redirectionSnapshot) healthCheck {
	const label = "KVM enabled"

	if cmd.WSMan == nil {
		return healthCheck{label, checkSkip, skipWSMANRequired}
	}

	if !redirection.ok {
		return healthCheck{label, checkWarn, "could not read redirection service"}
	}

	// enabledState==2 is the CIM standard "Enabled"; AMT also reports extended
	// values >=32768 (e.g. 32771) for session-active states. listenerEnabled is
	// the reliable signal that KVM will accept incoming connections.
	enabled := redirection.listenerEnabled && (redirection.enabledState == 2 || redirection.enabledState >= 32768)
	result.KVMEnabled = &enabled

	if enabled {
		return healthCheck{label, checkPass, fmt.Sprintf("redirection listener enabled (enabledState=%d)", redirection.enabledState)}
	}

	return healthCheck{label, checkWarn, fmt.Sprintf("enabledState=%d listener=%t", redirection.enabledState, redirection.listenerEnabled)}
}

// hostCheck tests TCP reachability of the optional --host target. The bool
// return reports whether a host was provided (and therefore a check produced).
// Reachability gates manageability, not provisioning, so an unreachable host
// is a warning rather than a failure.
func (cmd *StatusCmd) hostCheck(result *StatusResult) (healthCheck, bool) {
	if strings.TrimSpace(cmd.Host) == "" {
		return healthCheck{}, false
	}

	target := resolveHostTarget(cmd.Host)
	result.Host = target

	reachable := statusDialTCP(target, statusDialTimeout) == nil
	result.HostReachable = &reachable

	label := "Host reachable (" + target + ")"

	if reachable {
		return healthCheck{label, checkPass, "reachable"}, true
	}

	return healthCheck{label, checkWarn, "unreachable (device would not be manageable)"}, true
}

// lmsReachable probes both LMS local ports and returns the first open port,
// reporting whether LMS is listening on either.
func lmsReachable() (string, bool) {
	for _, port := range []string{utils.LMSPort, utils.LMSTLSPort} {
		if statusDialTCP(net.JoinHostPort(utils.LMSAddress, port), statusDialTimeout) == nil {
			return port, true
		}
	}

	return "", false
}

// resolveHostTarget normalizes a user-supplied host into host:port, defaulting
// the port to 443 when one is not specified.
func resolveHostTarget(host string) string {
	host = strings.TrimSpace(host)

	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return net.JoinHostPort(host, defaultHostPort)
	}

	if p == "" {
		p = defaultHostPort
	}

	return net.JoinHostPort(h, p)
}

func isActivatedControlMode(controlMode int) bool {
	return controlMode == ControlModeCCM || controlMode == ControlModeACM
}

func tlsModeLabel(item wsmantls.SettingDataResponse) string {
	switch {
	case item.Enabled && !item.AcceptNonSecureConnections && !item.MutualAuthentication:
		return "Server"
	case item.Enabled && item.AcceptNonSecureConnections && !item.MutualAuthentication:
		return "ServerAndNonTLS"
	case item.Enabled && !item.AcceptNonSecureConnections && item.MutualAuthentication:
		return "Mutual"
	case item.Enabled && item.AcceptNonSecureConnections && item.MutualAuthentication:
		return "MutualAndNonTLS"
	case !item.Enabled:
		return tlsModeNone
	default:
		return tlsModeUnknown
	}
}

func formatUserConsent(optInRequired uint32) string {
	switch optInRequired {
	case 0:
		return "none"
	case 1:
		return "kvm"
	case 4294967295:
		return "all"
	default:
		return fmt.Sprintf("unknown(%d)", optInRequired)
	}
}

// renderStatus writes the human-readable readiness report. Labels are padded
// to a common width (measured, not forced via lipgloss Width which would wrap
// long labels) so the detail column lines up.
func renderStatus(w io.Writer, result StatusResult, checks []healthCheck) {
	var b strings.Builder

	header := "AMT Provisioning Readiness"
	if result.SelectedCheckSet == checkSetPostActivation {
		header = "AMT Manageability Health"
	}

	b.WriteString(renderInfoHeader(header))
	b.WriteString(infoIndent + infoDimStyle.Render("Detected state: "+detectedState(result)) + "\n")
	b.WriteString(infoIndent + infoDimStyle.Render("Selected checks: "+selectedChecksLabel(result.SelectedCheckSet)) + "\n\n")

	if result.PartialEvaluation {
		b.WriteString(infoIndent + infoYellowStyle.Render("Evaluation: partial") + "  " + infoDimStyle.Render(result.PartialReason) + "\n\n")
	}

	labelWidth := 0
	for _, c := range checks {
		if width := lipgloss.Width(c.label); width > labelWidth {
			labelWidth = width
		}
	}

	for _, c := range checks {
		pad := strings.Repeat(" ", labelWidth-lipgloss.Width(c.label))
		b.WriteString(infoIndent + c.state.symbol() + "  " + c.label + pad)

		if c.detail != "" {
			b.WriteString("  " + infoDimStyle.Render(c.detail))
		}

		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(indentBlock(renderVerdict(result), infoIndent))
	b.WriteString("\n")

	if result.SelectedCheckSet == checkSetPreActivation && !result.LMSInstalled {
		b.WriteString("\n" + infoIndent + infoYellowStyle.Render("LMS features not available, e.g.:") + "\n")

		for _, feature := range lmsDependentFeatures {
			b.WriteString(infoIndent + infoIndent + infoDimStyle.Render("• "+feature) + "\n")
		}
	}

	b.WriteString("\n")

	fmt.Fprint(w, b.String())
}

// Verdict summary messages — single source of truth, asserted by tests.
// These messages summarize the device readiness assessment for provisioning and management.
const (
	verdictNoAMT           = "Device does not have AMT"
	verdictUnknownPriv     = "AMT status unknown (run as administrator)"
	verdictAlreadyActive   = "AMT device is already activated"
	verdictCannotProvision = "AMT cannot be provisioned"
	verdictNotManaged      = "AMT can be provisioned, but not managed"
	verdictReady           = "AMT device ready to be provisioned"
	verdictPostHealthy     = "Device is fully configured and ready for remote management"
	verdictPostPartial     = "Some prerequisites missing or not fully configured"
	verdictPostUnhealthy   = "Device requires attention before management workflows can proceed"
)

// renderVerdict renders the final summary box, applying the per-state color to
// the shared box style.
func renderVerdict(result StatusResult) string {
	color, msg := verdictColor(result, utils.IsElevated(), amtCapableArch())

	return verdictBoxStyle.Foreground(color).BorderForeground(color).Render(msg)
}

// verdictColor maps the gathered result to a summary color and message. It is
// pure (elevation and arch passed in) so it can be tested deterministically.
// Priority, highest first:
//   - no MEI driver on an AMT-capable arch while unelevated: undeterminable;
//   - no MEI driver otherwise (non-x86 arch, or elevated x86): not an AMT device;
//   - already activated: not a provisioning candidate;
//   - not provisionable: missing a network link;
//   - provisionable but --host unreachable: can provision, but not manage;
//   - ready.
func verdictColor(result StatusResult, elevated, amtCapable bool) (lipgloss.Color, string) {
	hostUnreachable := result.HostReachable != nil && !*result.HostReachable

	switch {
	case !result.MEIDriverPresent && amtCapable && !elevated:
		return lipgloss.Color("220"), verdictUnknownPriv
	case !result.MEIDriverPresent:
		return lipgloss.Color("168"), verdictNoAMT
	case result.SelectedCheckSet == checkSetPostActivation && result.ManageableInProduction:
		return lipgloss.Color("78"), verdictPostHealthy
	case result.SelectedCheckSet == checkSetPostActivation && result.PartialEvaluation:
		return lipgloss.Color("220"), verdictPostPartial
	case result.SelectedCheckSet == checkSetPostActivation:
		return lipgloss.Color("220"), verdictPostUnhealthy
	case result.AlreadyActivated:
		return lipgloss.Color("39"), verdictAlreadyActive
	case !result.ReadyToProvision:
		return lipgloss.Color("168"), verdictCannotProvision
	case hostUnreachable:
		return lipgloss.Color("220"), verdictNotManaged
	default:
		return lipgloss.Color("78"), verdictReady
	}
}

func detectedState(result StatusResult) string {
	if result.ControlMode != "" {
		return result.ControlMode
	}

	if result.MEIDriverPresent {
		return "unknown AMT state"
	}

	return "AMT unavailable"
}

func selectedChecksLabel(selected string) string {
	switch selected {
	case checkSetPostActivation:
		return "post-activation"
	case checkSetPreActivation:
		return "pre-activation"
	default:
		return checkStateUnknown
	}
}

func detectedStateKey(result StatusResult) string {
	switch {
	case !result.MEIDriverPresent:
		return "amt_unavailable"
	case result.AlreadyActivated && strings.Contains(strings.ToLower(result.ControlMode), "admin"):
		return "activated_acm"
	case result.AlreadyActivated && strings.Contains(strings.ToLower(result.ControlMode), "client"):
		return "activated_ccm"
	case result.AlreadyActivated:
		return checkStateActivated
	case result.MEIDriverPresent:
		return "pre_provisioning"
	default:
		return checkStateUnknown
	}
}

func overallResult(result StatusResult) string {
	switch {
	case !result.MEIDriverPresent && amtCapableArch() && !utils.IsElevated():
		return checkStateUnknown
	case !result.MEIDriverPresent:
		return "not_amt"
	case result.SelectedCheckSet == checkSetPostActivation && result.ManageableInProduction:
		return "healthy"
	case result.SelectedCheckSet == checkSetPostActivation && result.PartialEvaluation:
		return "partial"
	case result.SelectedCheckSet == checkSetPostActivation:
		return "warning"
	case result.ReadyToProvision && result.HostReachable != nil && !*result.HostReachable:
		return "warning"
	case result.ReadyToProvision:
		return "ready"
	default:
		return "not_ready"
	}
}

func checkStatusName(state checkState) string {
	switch state {
	case checkPass:
		return checkStatusPass
	case checkWarn:
		return "warn"
	case checkFail:
		return "fail"
	case checkSkip:
		return "skip"
	default:
		return "skip"
	}
}

func checkID(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	replacer := strings.NewReplacer(
		"(", " ",
		")", " ",
		"/", " ",
		"-", " ",
		",", " ",
		":", " ",
	)
	label = replacer.Replace(label)

	return strings.Join(strings.Fields(label), "_")
}

func jsonChecks(checks []healthCheck) []statusJSONCheck {
	out := make([]statusJSONCheck, 0, len(checks))
	for _, c := range checks {
		out = append(out, statusJSONCheck{
			ID:      checkID(c.label),
			Name:    c.label,
			Status:  checkStatusName(c.state),
			Message: c.detail,
		})
	}

	return out
}

// outputStatusJSON writes the machine-readable status result.
func outputStatusJSON(w io.Writer, result StatusResult, checks []healthCheck) error {
	payload := statusJSONOutput{
		StatusResult:     result,
		DetectedState:    detectedStateKey(result),
		SelectedCheckSet: result.SelectedCheckSet,
		OverallResult:    overallResult(result),
		Checks:           jsonChecks(checks),
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal status JSON: %w", err)
	}

	fmt.Fprintln(w, string(data))

	return nil
}
