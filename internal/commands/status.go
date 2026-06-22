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
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	wsmanboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/boot"
	wsmantls "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/version"
	log "github.com/sirupsen/logrus"
)

// Defaults for the status (health) checks.
const (
	statusDialTimeout       = 2 * time.Second
	defaultHostPort         = "443"
	dnsSuffixCheckLabel     = "DNS suffix (AMT vs OS)"
	linkReadinessCheckLabel = "AMT wired/wireless link"
	// linkStatusUp is the AMT-reported value compared against; the display uses
	// the connected/disconnected wording below.
	linkStatusUp     = "up"
	linkConnected    = "connected"
	linkDisconnected = "disconnected"
	meVersionTimeout = 10 * time.Second
)

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

// statusGetLMSVersion is a package var so tests can stub the OS LMS version query.
var statusGetLMSVersion = utils.GetLMSVersion

// checkState models the outcome of a single readiness check.
type checkState int

const (
	checkPass        checkState = iota // requirement satisfied (green)
	checkWarn                          // warning (yellow)
	checkFail                          // blocker failure (red)
	checkSkip                          // not verified / not applicable (dim)
	checkUnavailable                   // required dependency missing (dim)
)

// Repeated string literals extracted as constants for goconst compliance.
const (
	checkSetPostActivation    = "post_activation"
	checkSetPreActivation     = "pre_activation"
	checkSetPostActivationACM = "post_activation_acm"
	checkSetPostActivationCCM = "post_activation_ccm"
	checkSetPreActivationACM  = "pre_activation_acm"
	checkSetPreActivationCCM  = "pre_activation_ccm"
	skipMEIRequired           = "unavailable (MEI driver required)"
	skipWSMANRequired         = "unavailable (WSMAN client required)"
	tlsModeNone               = "None"
	tlsModeUnknown            = "Unknown"
	checkStateActivated       = "activated"
	checkStateUnknown         = "unknown"
	checkStatusPass           = "pass"
	connectionModeDirect      = "Direct"
	connectionModeCIRA        = "CIRA"
	errReadAMTVersion         = "could not read AMT version"
	userConsentAll            = ^uint32(0)
)

// symbol renders the colored status glyph for the check state.
func (s checkState) symbol() string {
	switch s {
	case checkPass:
		return infoGreenStyle.Render("✓")
	case checkWarn:
		return infoYellowStyle.Render("!")
	case checkFail:
		return infoRedStyle.Render("✗")
	case checkSkip:
		return infoDimStyle.Render("·")
	case checkUnavailable:
		return infoDimStyle.Render("·")
	default:
		return infoDimStyle.Render("·")
	}
}

type healthCheck struct {
	label  string
	state  checkState
	detail string
}

// StatusResult is the machine-readable result of the status command.
type StatusResult struct {
	Command                string `json:"command,omitempty"`
	PasswordProvided       bool   `json:"passwordProvided,omitempty"`
	MEIDriverPresent       bool   `json:"meiDriverPresent"`
	AMTEnabledInBIOS       *bool  `json:"amtEnabledInBIOS,omitempty"`
	ControlMode            string `json:"controlMode,omitempty"`
	AMTVersion             string `json:"amtVersion,omitempty"`
	SelectedCheckSet       string `json:"selectedCheckSet"`
	AlreadyActivated       bool   `json:"alreadyActivated"`
	AMTDNSSuffix           string `json:"amtDnsSuffix,omitempty"`
	OSDNSSuffix            string `json:"osDnsSuffix,omitempty"`
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
	Metadata   statusJSONMetadata   `json:"metadata"`
	Evaluation statusJSONEvaluation `json:"evaluation"`
	Checks     []statusJSONCheck    `json:"checks"`
}

type statusJSONMetadata struct {
	Command          string `json:"command"`
	Timestamp        string `json:"timestamp"`
	RPCVersion       string `json:"rpcVersion"`
	Elevated         bool   `json:"elevated"`
	PasswordProvided bool   `json:"passwordProvided"`
}

type statusJSONEvaluation struct {
	DetectedState          string `json:"detectedState"`
	SelectedCheckSet       string `json:"selectedCheckSet"`
	PasswordContext        string `json:"passwordContext,omitempty"`
	OverallResult          string `json:"overallResult"`
	OverallStatus          string `json:"overallStatus"`
	TotalChecks            int    `json:"totalChecks"`
	Passed                 int    `json:"passed"`
	Warned                 int    `json:"warned"`
	Failed                 int    `json:"failed"`
	Skipped                int    `json:"skipped"`
	Unavailable            int    `json:"unavailable"`
	PartialEvaluation      bool   `json:"partialEvaluation,omitempty"`
	PartialReason          string `json:"partialReason,omitempty"`
	ReadyToProvision       bool   `json:"readyToProvision,omitempty"`
	ManageableInProduction bool   `json:"manageableInProduction,omitempty"`
}

type checkStats struct {
	passed      int
	warned      int
	failed      int
	skipped     int
	unavailable int
}

type redirectionSnapshot struct {
	ok              bool
	enabledState    int
	listenerEnabled bool
}

type statusCheckProfile int

const (
	statusProfileAuto statusCheckProfile = iota
	statusProfileACM
	statusProfileCCM
)

// StatusCmd reports whether the local device is ready to be provisioned or,
// once activated, whether it is healthy for day-2 manageability.
type StatusCmd struct {
	AMTBaseCmd

	Host              string `help:"Host[:port] to test network reachability against (default port 443)" name:"host"`
	ACM               bool   `help:"Run ACM-specific health checks" name:"acm"`
	CCM               bool   `help:"Run CCM-specific health checks" name:"ccm" aliases:"cm"`
	wsmanStatusDetail string `kong:"-"`
}

func (cmd *StatusCmd) Validate() error {
	if cmd.ACM && cmd.CCM {
		return fmt.Errorf("--acm and --ccm cannot be used together")
	}

	return nil
}

func (cmd *StatusCmd) checkProfile() statusCheckProfile {
	if cmd.ACM {
		return statusProfileACM
	}

	if cmd.CCM {
		return statusProfileCCM
	}

	return statusProfileAuto
}

func selectedCheckSet(profile statusCheckProfile, activated bool) string {
	if activated {
		switch profile {
		case statusProfileAuto:
			return checkSetPostActivation
		case statusProfileACM:
			return checkSetPostActivationACM
		case statusProfileCCM:
			return checkSetPostActivationCCM
		default:
			return checkSetPostActivation
		}
	}

	switch profile {
	case statusProfileAuto:
		return checkSetPreActivation
	case statusProfileACM:
		return checkSetPreActivationACM
	case statusProfileCCM:
		return checkSetPreActivationCCM
	default:
		return checkSetPreActivation
	}
}

// RequiresAMTPassword indicates this command never prompts for an AMT password.
// A password may still be provided explicitly with --password for WSMAN-only
// post-activation checks, but the command does not require an interactive prompt.
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

	// Only prompt for elevation if it could actually unlock AMT-dependent checks.
	// Permanent HECI failures (e.g. non-vPro / missing MEI) are not fixable by
	// elevation and should be reported as status data instead of prompting.
	if !cmd.HECIAvailable && !utils.IsElevated() && amtCapableArch() &&
		!isPermanentHECIErrorText(cmd.HECIError) {
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

		cmd.WSMan = nil

		cmd.wsmanStatusDetail = "could not initialize WSMAN client"
	}
}

// gather runs every readiness check and computes the overall verdict.
func (cmd *StatusCmd) gather(ctx *Context) (StatusResult, []healthCheck) {
	result := StatusResult{
		Command:          "status",
		PasswordProvided: strings.TrimSpace(ctx.AMTPassword) != "",
	}
	profile := cmd.checkProfile()

	controlMode := cmd.controlModeCheck(&result)

	if result.AlreadyActivated {
		cmd.preparePostActivationWSMAN(ctx)

		result.SelectedCheckSet = selectedCheckSet(profile, true)

		return cmd.gatherPostActivation(ctx, result, profile)
	}

	result.SelectedCheckSet = selectedCheckSet(profile, false)

	return cmd.gatherPreActivation(ctx, result, controlMode, profile)
}

func (cmd *StatusCmd) gatherPreActivation(ctx *Context, result StatusResult, controlMode healthCheck, profile statusCheckProfile) (StatusResult, []healthCheck) {
	checks := make([]healthCheck, 0, 10)

	admin := cmd.adminCheck()

	checks = append(checks, admin)
	if admin.state == checkFail {
		result.ReadyToProvision = false

		return result, checks
	}

	mei := cmd.meiCheck(&result)

	checks = append(checks, mei)
	if mei.state == checkFail {
		result.ReadyToProvision = false

		return result, checks
	}

	platform := cmd.deviceTypeCheck(ctx, &result)
	checks = append(checks, platform)
	// Non-vPro: device identified but not eligible – stop before remaining checks.
	if result.DeviceType != "" &&
		!strings.Contains(result.DeviceType, "AMT Pro") &&
		!strings.Contains(result.DeviceType, "Intel Standard Manageability") {
		result.ReadyToProvision = false

		return result, checks
	}

	if platform.state == checkFail {
		result.ReadyToProvision = false

		return result, checks
	}

	checks = append(checks,
		cmd.amtEnabledInBIOSCheck(&result),
		cmd.amtVersionCheck(ctx, &result),
		cmd.dnsSuffixCheckForProfile(ctx, &result, profile),
		cmd.linkReadinessCheck(ctx, &result, profile),
		cmd.lmsCheck(&result),
		controlMode,
	)

	if hostCheck, ok := cmd.hostCheck(&result); ok {
		checks = append(checks, hostCheck)
	}

	result.ReadyToProvision = !hasBlockingFailure(checks)

	return result, checks
}

func (cmd *StatusCmd) gatherPostActivation(ctx *Context, result StatusResult, profile statusCheckProfile) (StatusResult, []healthCheck) {
	checks := make([]healthCheck, 0, 16)

	admin := cmd.adminCheck()

	checks = append(checks, admin)
	if admin.state == checkFail {
		result.ManageableInProduction = false

		return result, checks
	}

	mei := cmd.meiCheck(&result)

	checks = append(checks, mei)
	if mei.state == checkFail {
		result.ManageableInProduction = false

		return result, checks
	}

	checks = append(checks,
		cmd.deviceTypeCheck(ctx, &result),
		cmd.amtEnabledInBIOSCheck(&result),
		cmd.amtVersionCheck(ctx, &result),
		cmd.dnsSuffixCheckForProfile(ctx, &result, profile),
		cmd.linkReadinessCheck(ctx, &result, profile),
		cmd.lmsCheck(&result),
		cmd.modeAlignmentCheck(profile, result),
	)

	activated := cmd.activatedStateCheck(&result)
	wsman := cmd.wsmanAccessCheck(&result)
	connection := cmd.connectionModeCheck(ctx, &result)
	tlsTrust := cmd.tlsTrustCheck(&result)
	redirection := cmd.readRedirectionSnapshot()
	featurePolicy := cmd.featurePolicyCheck(&result, redirection)
	remoteManageability := cmd.remoteManageabilityCheck(&result)
	cmd.monitorCheck(&result) // populate result.MonitorConnected for kvmCheck; not a separate output row
	kvm := cmd.kvmCheck(&result, redirection)

	checks = append(checks,
		activated,
		wsman,
		connection,
	)

	// CIRA checks are only relevant when the device is using CIRA mode.
	if result.ConnectionMode != connectionModeDirect {
		checks = append(checks,
			cmd.ciraConfigCheck(&result),
			cmd.ciraConnectionCheck(&result),
			cmd.ciraPrerequisitesCheck(&result),
		)
	}

	checks = append(checks,
		tlsTrust,
		featurePolicy,
		remoteManageability,
		cmd.ocrBIOSCheck(&result),
		kvm,
	)

	result.ManageableInProduction = result.MEIDriverPresent && result.AlreadyActivated
	if result.WSMANAvailable == nil || !*result.WSMANAvailable {
		result.PartialEvaluation = true
		result.PartialReason = wsman.detail
		result.ManageableInProduction = false

		return result, checks
	}

	// Direct mode: WSMAN availability proves connectivity; CIRA/TLS gates are not applicable.
	if result.ConnectionMode == connectionModeDirect {
		result.ManageableInProduction = !hasBlockingFailure(checks)

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

	if hasBlockingFailure(checks) {
		result.ManageableInProduction = false
	}

	return result, checks
}

func hasBlockingFailure(checks []healthCheck) bool {
	for _, c := range checks {
		if c.state == checkFail {
			return true
		}
	}

	return false
}

func summarizeChecks(checks []healthCheck) checkStats {
	stats := checkStats{}

	for _, c := range checks {
		switch c.state {
		case checkPass:
			stats.passed++
		case checkWarn:
			stats.warned++
		case checkFail:
			stats.failed++
		case checkSkip:
			stats.skipped++
		case checkUnavailable:
			stats.unavailable++
		}
	}

	return stats
}

func groupChecksByState(checks []healthCheck) map[checkState][]healthCheck {
	grouped := map[checkState][]healthCheck{
		checkPass:        {},
		checkWarn:        {},
		checkFail:        {},
		checkSkip:        {},
		checkUnavailable: {},
	}

	for _, c := range checks {
		grouped[c.state] = append(grouped[c.state], c)
	}

	return grouped
}

func (cmd *StatusCmd) activatedStateCheck(result *StatusResult) healthCheck {
	const label = "AMT activated state"

	if !result.AlreadyActivated {
		return healthCheck{label, checkPass, "AMT activated state: Pre-provisioning"}
	}

	if strings.Contains(strings.ToLower(result.ControlMode), "admin") {
		return healthCheck{label, checkPass, "AMT activated state: Admin Control Mode"}
	}

	if strings.Contains(strings.ToLower(result.ControlMode), "client") {
		return healthCheck{label, checkPass, "AMT activated state: Client Control Mode"}
	}

	return healthCheck{label, checkPass, "AMT activated state: " + result.ControlMode}
}

func (cmd *StatusCmd) wsmanAccessCheck(result *StatusResult) healthCheck {
	const label = "Local WSMAN session"

	available := cmd.WSMan != nil
	result.WSMANAvailable = &available

	if available {
		return healthCheck{label, checkPass, "Local WSMAN session available"}
	}

	if cmd.wsmanStatusDetail != "" {
		return healthCheck{label, checkUnavailable, cmd.wsmanStatusDetail}
	}

	return healthCheck{label, checkUnavailable, "WSMAN-based checks unavailable"}
}

func (cmd *StatusCmd) adminCheck() healthCheck {
	const label = "Running as admin/root"

	if utils.IsElevated() || cmd.HECIAvailable || isPermanentHECIErrorText(cmd.HECIError) {
		return healthCheck{label, checkPass, "Running as admin/root"}
	}

	return healthCheck{label, checkFail, "Running as admin/root — cannot access MEI"}
}

// meiCheck reports whether the MEI/HECI driver is present (i.e. this is an AMT device).
func (cmd *StatusCmd) meiCheck(result *StatusResult) healthCheck {
	const label = "MEI driver"

	result.MEIDriverPresent = cmd.HECIAvailable

	if cmd.HECIAvailable {
		ver := strings.TrimSpace(utils.GetMEIDriverVersion())
		if ver == "" {
			return healthCheck{label, checkPass, "Intel MEI driver installed and responding — current"}
		}

		return healthCheck{label, checkPass, "Intel MEI driver installed and responding — " + ver + ", current"}
	}

	// A permanent HECI error indicates a real Intel ME device without AMT support
	// (for example, non-vPro hardware or a missing/invalid MEI stack), not an
	// elevation problem that can be fixed by running as admin/root.
	if isPermanentHECIErrorText(cmd.HECIError) {
		result.MEIDriverPresent = true

		return healthCheck{label, checkPass, "Intel MEI driver installed, non-AMT Intel ME device"}
	}

	if !amtCapableArch() {
		return healthCheck{label, checkFail, "Intel MEI driver not installed"}
	}

	if !utils.IsElevated() {
		return healthCheck{label, checkFail, "Running as admin/root — cannot access MEI"}
	}

	return healthCheck{label, checkFail, "Intel MEI driver not installed"}
}

func (cmd *StatusCmd) amtEnabledInBIOSCheck(result *StatusResult) healthCheck {
	const label = "MEBx enabled in BIOS"

	enabled := cmd.HECIAvailable
	result.AMTEnabledInBIOS = &enabled

	if enabled {
		return healthCheck{label, checkPass, "MEBx enabled in BIOS"}
	}

	return healthCheck{label, checkFail, "MEBx disabled in BIOS"}
}

func (cmd *StatusCmd) amtVersionCheck(ctx *Context, result *StatusResult) healthCheck {
	const label = "AMT version"

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		return healthCheck{label, checkUnavailable, skipMEIRequired}
	}

	if strings.TrimSpace(result.AMTVersion) == "" {
		ver, err := ctx.AMTCommand.GetVersionDataFromME("AMT", meVersionTimeout)
		if err != nil || strings.TrimSpace(ver) == "" {
			return healthCheck{label, checkWarn, errReadAMTVersion}
		}

		result.AMTVersion = strings.TrimSpace(ver)
	}

	if result.AMTVersion == "" {
		return healthCheck{label, checkWarn, errReadAMTVersion}
	}

	major := parseMajorVersion(result.AMTVersion)
	if major >= 11 && major <= 21 {
		return healthCheck{label, checkPass, "AMT version " + result.AMTVersion + " (supported)"}
	}

	return healthCheck{label, checkWarn, "AMT version " + result.AMTVersion + " (not supported)"}
}

func parseMajorVersion(version string) int {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) == 0 {
		return 0
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}

	return major
}

// controlModeCheck reports the activation state. Pre-provisioning (control
// mode 0) is the green, ready-to-activate state; an already-activated device
// (CCM/ACM) is flagged so the verdict reports it rather than "ready".
func (cmd *StatusCmd) controlModeCheck(result *StatusResult) healthCheck {
	const label = "AMT activated state"

	if !cmd.HECIAvailable {
		return healthCheck{label, checkUnavailable, skipMEIRequired}
	}

	result.ControlMode = utils.InterpretControlMode(cmd.ControlMode)

	switch cmd.ControlMode {
	case ControlModeCCM, ControlModeACM:
		result.AlreadyActivated = true

		if cmd.ControlMode == ControlModeACM {
			return healthCheck{label, checkPass, "AMT activated state: Admin Control Mode"}
		}

		return healthCheck{label, checkPass, "AMT activated state: Client Control Mode"}
	default:
		return healthCheck{label, checkPass, "AMT activated state: Pre-provisioning"}
	}
}

// dnsSuffixCheck validates AMT DNS suffix baseline for ACM workflows.
// AMT suffix must be configured; OS mismatch is a warning because valid
// environments can provision with a cert/profile domain independent of host OS.
func (cmd *StatusCmd) dnsSuffixCheck(ctx *Context, result *StatusResult) healthCheck {
	const label = dnsSuffixCheckLabel

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		return healthCheck{label, checkUnavailable, skipMEIRequired}
	}

	amtSuffix, err := ctx.AMTCommand.GetDNSSuffix()
	if err != nil {
		return healthCheck{label, checkWarn, "could not read AMT DNS suffix"}
	}

	result.AMTDNSSuffix = strings.TrimSpace(amtSuffix)

	osSuffix, err := ctx.AMTCommand.GetOSDNSSuffix()
	if err == nil {
		result.OSDNSSuffix = strings.TrimSpace(osSuffix)
	}

	if result.AMTDNSSuffix == "" {
		if result.OSDNSSuffix != "" {
			return healthCheck{label, checkFail, "OS DNS suffix configured: " + result.OSDNSSuffix + ", AMT DNS suffix not configured"}
		}

		return healthCheck{label, checkFail, "DNS suffix not configured - cannot activate to ACM"}
	}

	if result.OSDNSSuffix == "" {
		return healthCheck{label, checkPass, "DNS suffix configured: " + result.AMTDNSSuffix}
	}

	if strings.EqualFold(result.AMTDNSSuffix, result.OSDNSSuffix) {
		result.DNSSuffixMatch = true

		return healthCheck{label, checkPass, "DNS suffix configured: " + result.AMTDNSSuffix}
	}

	return healthCheck{label, checkWarn, "AMT=" + result.AMTDNSSuffix + " OS=" + result.OSDNSSuffix + " (verify provisioning cert/profile domain alignment)"}
}

func (cmd *StatusCmd) dnsSuffixCheckForProfile(ctx *Context, result *StatusResult, profile statusCheckProfile) healthCheck {
	check := cmd.dnsSuffixCheck(ctx, result)
	if profile == statusProfileACM {
		return check
	}

	if check.state == checkFail {
		check.state = checkWarn
		check.detail += " (ACM-only blocker; CCM can still proceed)"
	}

	return check
}

// deviceTypeCheck reports whether the device is a full AMT vPro or a limited
// Intel Standard Manageability (ISM) product. ISM lacks KVM, SOL, and other
// advanced provisioning capabilities.
func (cmd *StatusCmd) deviceTypeCheck(ctx *Context, result *StatusResult) healthCheck {
	const label = "Platform type"

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		if isPermanentHECIErrorText(cmd.HECIError) {
			result.DeviceType = "non-vPro Intel ME device"

			return healthCheck{label, checkPass, "Platform type: non-vPro, contact Intel for manual checks"}
		}

		return healthCheck{label, checkUnavailable, skipMEIRequired}
	}

	sku, err := ctx.AMTCommand.GetVersionDataFromME("Sku", meVersionTimeout)
	if err != nil {
		return healthCheck{label, checkWarn, "could not read device SKU"}
	}

	ver := strings.TrimSpace(result.AMTVersion)

	var amtErr error
	if ver == "" {
		ver, amtErr = ctx.AMTCommand.GetVersionDataFromME("AMT", meVersionTimeout)
	}

	if amtErr != nil {
		return healthCheck{label, checkWarn, errReadAMTVersion}
	}

	result.AMTVersion = strings.TrimSpace(ver)

	features := utils.DecodeAMTFeatures(ver, sku)
	result.DeviceType = features

	switch {
	case strings.Contains(features, "AMT Pro"):
		return healthCheck{label, checkPass, "Platform type: vPro"}
	case strings.Contains(features, "Intel Standard Manageability"):
		return healthCheck{label, checkPass, "Platform type: ISM"}
	default:
		return healthCheck{label, checkPass, "Platform type: non-vPro, contact Intel for manual checks"}
	}
}

// lmsCheck reports whether the Local Manageability Service is listening locally.
// LMS serves the plain port (16992) and, on TLS-enforced devices, the TLS port
// (16993); either being open means LMS is present.
func (cmd *StatusCmd) lmsCheck(result *StatusResult) healthCheck {
	const label = "LMS (Local Manageability Service)"

	_, ok := lmsReachable()
	installedVersion := strings.TrimSpace(statusGetLMSVersion())
	result.LMSInstalled = ok || installedVersion != ""

	if ok {
		if installedVersion != "" {
			return healthCheck{label, checkPass, "LMS installed, running — " + installedVersion + ", current"}
		}

		return healthCheck{label, checkPass, "LMS installed, running — current"}
	}

	if installedVersion != "" {
		return healthCheck{label, checkWarn, "LMS installed but not running — recommend starting LMS service"}
	}

	return healthCheck{label, checkWarn, "LMS not installed. Install LMS"}
}

// linkReadinessCheck evaluates wired/wireless readiness using the matrix semantics.
func (cmd *StatusCmd) linkReadinessCheck(ctx *Context, result *StatusResult, profile statusCheckProfile) healthCheck {
	const label = linkReadinessCheckLabel

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		return healthCheck{label, checkUnavailable, skipMEIRequired}
	}

	wired, wiredErr := ctx.AMTCommand.GetLANInterfaceSettings(false)
	if wiredErr != nil {
		log.Debugf("failed to read wired LAN interface settings: %v", wiredErr)

		return healthCheck{label, checkWarn, "could not read link status"}
	}

	wireless, wirelessErr := ctx.AMTCommand.GetLANInterfaceSettings(true)
	if wirelessErr != nil {
		log.Debugf("failed to read wireless LAN interface settings: %v", wirelessErr)
	}

	result.WiredSupported = wired.IsEnabled || wired.LinkStatus != "" || wired.MACAddress != "" || wired.IPAddress != "" || wired.OsIPAddress != ""
	result.WirelessSupported = wireless.IsEnabled || wireless.LinkStatus != "" || wireless.MACAddress != "" || wireless.IPAddress != "" || wireless.OsIPAddress != ""

	result.WiredLinkUp = strings.EqualFold(wired.LinkStatus, linkStatusUp)
	result.WirelessLinkUp = strings.EqualFold(wireless.LinkStatus, linkStatusUp)

	if profile == statusProfileCCM {
		if result.WiredLinkUp || result.WirelessLinkUp {
			return healthCheck{label, checkPass, "AMT network link available for CCM checks"}
		}

		return healthCheck{label, checkWarn, "No AMT network link detected (ACM would require wired link; CCM can still proceed locally)"}
	}

	if result.WiredLinkUp {
		return healthCheck{label, checkPass, "AMT wired link up"}
	}

	if result.WirelessLinkUp {
		return healthCheck{label, checkFail, "Wired link is down. ACM activation cannot be done"}
	}

	if strings.TrimSpace(result.AMTDNSSuffix) == "" {
		return healthCheck{label, checkFail, "Wired link down and no AMT DNS suffix"}
	}

	if !result.WirelessSupported || wirelessErr != nil {
		return healthCheck{label, checkFail, "Wired link down and wireless not supported - cannot activate to ACM"}
	}

	return healthCheck{label, checkFail, "Wired link is down. ACM activation cannot be done"}
}

func (cmd *StatusCmd) modeAlignmentCheck(profile statusCheckProfile, result StatusResult) healthCheck {
	const label = "Requested mode alignment"

	if profile == statusProfileAuto {
		return healthCheck{label, checkSkip, "auto mode (no --acm/--ccm constraint requested)"}
	}

	if profile == statusProfileACM {
		if strings.Contains(strings.ToLower(result.ControlMode), "admin") {
			return healthCheck{label, checkPass, "device is in Admin Control Mode (ACM)"}
		}

		return healthCheck{label, checkFail, "--acm requested but device is not in Admin Control Mode"}
	}

	if strings.Contains(strings.ToLower(result.ControlMode), "client") {
		return healthCheck{label, checkPass, "device is in Client Control Mode (CCM)"}
	}

	return healthCheck{label, checkFail, "--ccm/--cm requested but device is not in Client Control Mode"}
}

func (cmd *StatusCmd) connectionModeCheck(ctx *Context, result *StatusResult) healthCheck {
	const label = "AMT Connection Mode"

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		return healthCheck{label, checkUnavailable, skipMEIRequired}
	}

	status, err := ctx.AMTCommand.GetRemoteAccessConnectionStatus()
	if err != nil {
		return healthCheck{label, checkWarn, "could not read remote access status"}
	}

	mode := connectionModeDirect
	if strings.Contains(strings.ToLower(status.NetworkStatus), "cira") {
		mode = connectionModeCIRA
	}

	result.ConnectionMode = mode
	result.MPSHostname = status.MPSHostname
	result.MPSPort = status.MPSPort

	if mode == connectionModeDirect {
		return healthCheck{label, checkPass, "AMT Connection Mode: Direct"}
	}

	// CIRAConnected is only meaningful when CIRA mode is detected.
	connected := strings.EqualFold(status.RemoteStatus, linkConnected)
	result.CIRAConnected = &connected

	remote := strings.ToLower(strings.TrimSpace(status.RemoteStatus))
	switch remote {
	case linkConnected:
		return healthCheck{label, checkPass, "AMT Connection Mode: CIRA and Connected to MPS"}
	case "connecting":
		return healthCheck{label, checkWarn, "AMT Connection Mode: CIRA and Connecting to MPS"}
	case "disconnected":
		return healthCheck{label, checkFail, "AMT Connection Mode: CIRA and Disconnected to MPS"}
	default:
		return healthCheck{label, checkWarn, "AMT Connection Mode: CIRA and state unknown"}
	}
}

func (cmd *StatusCmd) tlsTrustCheck(result *StatusResult) healthCheck {
	const label = "TLS configuration / trust inventory"

	if cmd.WSMan == nil {
		return healthCheck{label, checkUnavailable, skipWSMANRequired}
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
		return healthCheck{label, checkUnavailable, skipWSMANRequired}
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
	} else if strings.EqualFold(result.ConnectionMode, connectionModeCIRA) && strings.TrimSpace(result.MPSHostname) != "" {
		port := result.MPSPort
		if port == 0 {
			port = 443
		}

		target = net.JoinHostPort(result.MPSHostname, strconv.Itoa(port))

		source = "MPS"
	}

	if target == "" {
		if result.ConnectionMode == connectionModeDirect {
			return healthCheck{label, checkSkip, "direct mode: use --host <console-address> to probe console reachability"}
		}

		return healthCheck{label, checkSkip, "no management endpoint available for local probe"}
	}

	reachable := statusDialTCP(target, statusDialTimeout) == nil
	result.RemoteManageabilityUp = &reachable

	if reachable {
		return healthCheck{label, checkPass, source + " reachable from device at " + target}
	}

	// The OS-level probe to the MPS target is expected to fail when the ME firmware
	// owns the CIRA tunnel; only skip the failure when using the MPS-derived target
	// (not a user-supplied --host) and CIRA is confirmed connected.
	if source == "MPS" && result.CIRAConnected != nil && *result.CIRAConnected {
		result.RemoteManageabilityUp = ptrBool(true)

		return healthCheck{label, checkPass, source + " reachable via active CIRA tunnel (OS probe blocked at " + target + ")"}
	}

	return healthCheck{label, checkFail, source + " unreachable from device at " + target}
}

func (cmd *StatusCmd) ciraConfigCheck(result *StatusResult) healthCheck {
	const label = "CIRA configuration"

	if cmd.WSMan == nil {
		return healthCheck{label, checkUnavailable, skipWSMANRequired}
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
		policyWord := "policies"
		if len(policies) == 1 {
			policyWord = "policy"
		}

		serverWord := "servers"
		if len(mps) == 1 {
			serverWord = "server"
		}

		return healthCheck{label, checkPass, fmt.Sprintf("CIRA configured: %d remote access %s, %d MPS %s", len(policies), policyWord, len(mps), serverWord)}
	}

	return healthCheck{label, checkWarn, "no CIRA policy/MPS mapping found"}
}

func (cmd *StatusCmd) ciraConnectionCheck(result *StatusResult) healthCheck {
	const label = "CIRA connected"

	if result.ConnectionMode != connectionModeCIRA {
		return healthCheck{label, checkSkip, "device is in direct-connect mode"}
	}

	if result.CIRAConnected == nil {
		return healthCheck{label, checkSkip, "remote access status unavailable"}
	}

	if *result.CIRAConnected {
		return healthCheck{label, checkPass, "CIRA tunnel active"}
	}

	return healthCheck{label, checkFail, "CIRA tunnel not active — device unreachable via CIRA"}
}

func (cmd *StatusCmd) ciraPrerequisitesCheck(result *StatusResult) healthCheck {
	const label = "CIRA prerequisites"

	if cmd.WSMan == nil {
		return healthCheck{label, checkUnavailable, skipWSMANRequired}
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

	if strings.Contains(result.DeviceType, "Intel Standard Manageability") {
		notSupported := false
		result.OCRBIOSVerified = &notSupported

		return healthCheck{label, checkPass, "OCR not supported, ISM Device"}
	}

	if cmd.WSMan == nil {
		result.OCRBIOSVerified = nil

		return healthCheck{label, checkUnavailable, skipWSMANRequired}
	}

	bootSettings, err := cmd.WSMan.GetBootSettingData()
	if err != nil {
		result.OCRBIOSVerified = nil

		return healthCheck{label, checkUnavailable, "could not read OCR boot settings"}
	}

	enabled := isOCREnabled(bootSettings)

	result.OCRBIOSVerified = &enabled
	if enabled {
		return healthCheck{label, checkPass, "OCR supported and enabled"}
	}

	return healthCheck{label, checkWarn, "OCR supported, not enabled"}
}

func isOCREnabled(bootSettings wsmanboot.Response) bool {
	b := bootSettings.Body.BootSettingDataGetResponse

	// OCR can be represented by one-click-recovery related BIOS toggles.
	return b.UEFIHTTPSBootEnabled || b.UEFILocalPBABootEnabled || b.WinREBootEnabled
}

func (cmd *StatusCmd) monitorCheck(result *StatusResult) healthCheck {
	const label = "Monitor connected for KVM"

	connected := statusDetectMonitorConnected()
	result.MonitorConnected = connected

	if connected == nil {
		return healthCheck{label, checkSkip, "could not determine monitor state"}
	}

	if *connected {
		// physical display detected via OS DRM subsystem (/sys/class/drm)
		return healthCheck{label, checkPass, "physical display detected"}
	}

	return healthCheck{label, checkWarn, "no physical display detected"}
}

func (cmd *StatusCmd) kvmCheck(result *StatusResult, redirection redirectionSnapshot) healthCheck {
	const label = "KVM enabled"

	if strings.Contains(result.DeviceType, "Intel Standard Manageability") {
		result.KVMEnabled = nil

		return healthCheck{label, checkPass, "KVM not supported, ISM Device"}
	}

	if cmd.WSMan == nil {
		return healthCheck{label, checkUnavailable, skipWSMANRequired}
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
		if result.MonitorConnected != nil && *result.MonitorConnected {
			return healthCheck{label, checkPass, "KVM enabled, monitor connected"}
		}

		return healthCheck{label, checkWarn, "KVM enabled, monitor not connected"}
	}

	return healthCheck{label, checkWarn, "KVM not enabled"}
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

	label := "Host reachable"

	if reachable {
		return healthCheck{label, checkPass, target + " reachable"}, true
	}

	return healthCheck{label, checkWarn, target + " unreachable (device would not be manageable)"}, true
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

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return net.JoinHostPort(strings.Trim(host, "[]"), defaultHostPort)
	}

	// Bracketed IPv6 with trailing colon — strip the port separator before parsing.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]:") {
		host = strings.TrimSuffix(host, ":")

		return net.JoinHostPort(strings.Trim(host, "[]"), defaultHostPort)
	}

	// Handle common "host:" input while preserving IPv6 forms.
	if strings.HasSuffix(host, ":") && strings.Count(host, ":") == 1 && !strings.HasPrefix(host, "[") {
		host = strings.TrimSuffix(host, ":")
	}

	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return net.JoinHostPort(host, defaultHostPort)
	}

	if p == "" {
		p = defaultHostPort
	}

	return net.JoinHostPort(h, p)
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
	case userConsentAll:
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

	postActivation := isPostActivationSelected(result.SelectedCheckSet)

	grouped := groupChecksByState(checks)

	b.WriteString(renderInfoHeader("AMT Health Check"))
	b.WriteString(infoIndent + infoDimStyle.Render("Detected state: "+detectedState(result)) + "\n")
	b.WriteString(infoIndent + infoDimStyle.Render("Selected checks: "+selectedChecksLabel(result.SelectedCheckSet)) + "\n\n")

	if postActivation {
		b.WriteString(infoIndent + infoDimStyle.Render("Password context: "+passwordContext(result)) + "\n\n")
	}

	appendSection := func(title string, state checkState) {
		rows := grouped[state]
		if len(rows) == 0 {
			return
		}

		b.WriteString(title + "\n")

		for _, c := range rows {
			line := c.detail
			if strings.TrimSpace(line) == "" {
				line = c.label
			}

			b.WriteString(infoIndent + c.state.symbol() + " " + line + "\n")
		}

		b.WriteString("\n")
	}

	appendSection("Passed", checkPass)
	appendSection("Warnings", checkWarn)
	appendSection("Failed", checkFail)

	// Combine skip + unavailable into the user-facing "Not verified" group.
	notVerified := append(grouped[checkSkip], grouped[checkUnavailable]...)
	if len(notVerified) > 0 {
		b.WriteString("Not verified\n")

		for _, c := range notVerified {
			line := c.detail
			if strings.TrimSpace(line) == "" {
				line = c.label
			}

			b.WriteString(infoIndent + c.state.symbol() + " " + line + "\n")
		}

		b.WriteString("\n")
	}

	summarySymbol, summaryText, nextAction := finalSummary(result, checks)
	b.WriteString(summarySymbol + " " + summaryText + "\n")
	b.WriteString("→ " + nextAction + "\n\n")

	b.WriteString("SKU Information\n")
	b.WriteString(infoIndent + "Processor: " + fallbackValue(utils.GetCPUModel()) + "\n")
	b.WriteString(infoIndent + "Wired Adapter: " + fallbackValue(wiredAdapterSummary(result)) + "\n")
	b.WriteString(infoIndent + "Wireless Adapter: " + fallbackValue(wirelessAdapterSummary(result)) + "\n")

	osInfo := utils.GetOSInfo()
	b.WriteString(infoIndent + "OS: " + fallbackValue(strings.TrimSpace(osInfo.Distro+" "+osInfo.Version)) + "\n\n")

	fmt.Fprint(w, b.String())
}

func filterChecksByState(checks []healthCheck, state checkState) []healthCheck {
	rows := make([]healthCheck, 0)

	for _, c := range checks {
		if c.state == state {
			rows = append(rows, c)
		}
	}

	return rows
}

func fallbackValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "<unavailable>"
	}

	return v
}

func wiredAdapterSummary(result StatusResult) string {
	if result.WiredSupported {
		if result.WiredLinkUp {
			return "supported, link up"
		}

		return "supported, link down"
	}

	return "not supported"
}

func wirelessAdapterSummary(result StatusResult) string {
	if result.WirelessSupported {
		if result.WirelessLinkUp {
			return "supported, link up"
		}

		return "supported, link down"
	}

	return "not supported"
}

func anyCheckWarn(checks []healthCheck, label string) bool {
	for _, c := range checks {
		if c.state == checkWarn && c.label == label {
			return true
		}
	}

	return false
}

func anyCheckWarnExcept(checks []healthCheck, excludeLabel string) bool {
	for _, c := range checks {
		if c.state == checkWarn && c.label != excludeLabel {
			return true
		}
	}

	return false
}

func ptrBool(v bool) *bool {
	return &v
}

func isPostActivationSelected(selected string) bool {
	return strings.HasPrefix(selected, checkSetPostActivation)
}

func onlyACMBlockerFailures(checks []healthCheck) bool {
	failed := filterChecksByState(checks, checkFail)
	if len(failed) == 0 {
		return false
	}

	for _, c := range failed {
		if c.label != dnsSuffixCheckLabel && c.label != linkReadinessCheckLabel {
			return false
		}
	}

	return true
}

func onlyCCMBypassWarnings(checks []healthCheck) bool {
	warned := filterChecksByState(checks, checkWarn)
	if len(warned) == 0 {
		return false
	}

	for _, c := range warned {
		if !strings.Contains(c.detail, "CCM can still proceed") {
			return false
		}
	}

	return true
}

func finalSummary(result StatusResult, checks []healthCheck) (string, string, string) {
	stats := summarizeChecks(checks)
	postActivation := isPostActivationSelected(result.SelectedCheckSet)

	if postActivation {
		if result.ManageableInProduction && stats.failed == 0 {
			return "✓", "Device is fully configured and ready for remote management.", "No action required."
		}

		if stats.failed > 0 {
			return "✗", "Device requires attention before management workflows can proceed.", "Resolve failed checks and re-run health check."
		}

		return "!", "Some prerequisites missing or not fully configured.", "Review warnings and re-run health check after remediation."
	}

	acmProfile := result.SelectedCheckSet == checkSetPreActivationACM
	ccmProfile := result.SelectedCheckSet == checkSetPreActivationCCM

	// Non-vPro: device type identified but platform is ineligible.
	if result.DeviceType != "" &&
		!strings.Contains(result.DeviceType, "AMT Pro") &&
		!strings.Contains(result.DeviceType, "Intel Standard Manageability") {
		return "✗", "Device is not eligible for ACM activation.", "Perform manual platform validation with Intel guidance."
	}

	if stats.failed > 0 {
		if ccmProfile {
			return "✗", "Device cannot be activated to CCM in current state.", "Address failed checks and re-run health check with --ccm/--cm."
		}

		if onlyACMBlockerFailures(checks) {
			return "!", "ACM prerequisites are not met, but CCM activation can still proceed.", "Proceed with CCM, or resolve DNS/wired prerequisites and re-run health check for ACM."
		}

		return "✗", "Device cannot be activated to ACM in current state.", "Address failed checks and re-run health check."
	}

	if stats.warned > 0 {
		if acmProfile {
			hasDNSWarn := anyCheckWarn(checks, dnsSuffixCheckLabel)
			hasOtherWarn := anyCheckWarnExcept(checks, dnsSuffixCheckLabel)

			if hasDNSWarn && !hasOtherWarn {
				return "!", "Device conditionally ready; ACM activation requires DNS domain alignment with the provisioning certificate/profile.", "Align the AMT DNS suffix to the provisioning cert/profile domain and re-run health check for ACM."
			}

			if hasDNSWarn && hasOtherWarn {
				return "!", "Device conditionally ready; verify provisioning-domain alignment and resolve other warnings before ACM activation.", "Ensure AMT DNS suffix aligns to provisioning cert/profile domain and address remaining warnings, then re-run health check."
			}

			return "!", "Device is conditionally ready for ACM activation; review warning checks before proceeding.", "Review warning checks and re-run health check after remediation."
		}

		if ccmProfile {
			if onlyCCMBypassWarnings(checks) {
				return "✓", "Device is ready for CCM activation.", "Proceed with CCM activation."
			}

			return "!", "Device appears CCM-capable with warnings.", "Review warning checks and proceed with CCM activation if acceptable."
		}

		hasDNSWarn := anyCheckWarn(checks, dnsSuffixCheckLabel)
		hasOtherWarn := anyCheckWarnExcept(checks, dnsSuffixCheckLabel)

		if hasDNSWarn && !hasOtherWarn {
			return "!", "Device conditionally ready; CCM activation can proceed, but ACM requires DNS domain alignment with the provisioning certificate/profile.", "Proceed with CCM, or align the AMT DNS suffix to the provisioning cert/profile domain and re-run health check for ACM."
		}

		if hasDNSWarn && hasOtherWarn {
			return "!", "Device conditionally ready; verify provisioning-domain alignment and resolve other warnings before activation.", "Ensure AMT DNS suffix aligns to provisioning cert/profile domain and address remaining warnings, then re-run health check."
		}

		return "!", "Device is conditionally ready; activation can proceed with operational risks.", "Review warning checks and re-run health check after remediation."
	}

	return "✓", "Device is ready for ACM activation.", "Proceed with ACM activation."
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
	postActivation := isPostActivationSelected(result.SelectedCheckSet)

	switch {
	case !result.MEIDriverPresent && amtCapable && !elevated:
		return lipgloss.Color("220"), verdictUnknownPriv
	case !result.MEIDriverPresent:
		return lipgloss.Color("168"), verdictNoAMT
	case postActivation && result.ManageableInProduction:
		return lipgloss.Color("78"), verdictPostHealthy
	case postActivation && result.PartialEvaluation:
		return lipgloss.Color("220"), verdictPostPartial
	case postActivation:
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
	if result.AlreadyActivated {
		if strings.Contains(strings.ToLower(result.ControlMode), "admin") {
			return "Admin Control Mode"
		}

		if strings.Contains(strings.ToLower(result.ControlMode), "client") {
			return "Client Control Mode"
		}

		if strings.TrimSpace(result.ControlMode) != "" {
			return result.ControlMode
		}
	}

	if result.MEIDriverPresent {
		return "Pre-provisioning"
	}

	return "AMT unavailable"
}

func passwordContext(result StatusResult) string {
	if !isPostActivationSelected(result.SelectedCheckSet) {
		return "not required"
	}

	if result.PasswordProvided {
		return "AMT password provided; full post-activation checks executed"
	}

	return "AMT password not provided; password-dependent checks are marked as Not verified"
}

func selectedChecksLabel(selected string) string {
	switch selected {
	case checkSetPostActivation:
		return "post-activation"
	case checkSetPostActivationACM:
		return "post-activation (ACM profile)"
	case checkSetPostActivationCCM:
		return "post-activation (CCM profile)"
	case checkSetPreActivation:
		return "pre-activation"
	case checkSetPreActivationACM:
		return "pre-activation (ACM profile)"
	case checkSetPreActivationCCM:
		return "pre-activation (CCM profile)"
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
	postActivation := isPostActivationSelected(result.SelectedCheckSet)

	switch {
	case !result.MEIDriverPresent && amtCapableArch() && !utils.IsElevated():
		return checkStateUnknown
	case !result.MEIDriverPresent:
		return "not_amt"
	case postActivation && result.ManageableInProduction:
		return "healthy"
	case postActivation && result.PartialEvaluation:
		return "partial"
	case postActivation:
		return "unhealthy"
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
	case checkUnavailable:
		return "unavailable"
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
	_, summaryText, _ := finalSummary(result, checks)
	stats := summarizeChecks(checks)
	vinfo := version.Get()

	payload := statusJSONOutput{
		Metadata: statusJSONMetadata{
			Command:          result.Command,
			Timestamp:        time.Now().Format(time.RFC3339),
			RPCVersion:       vinfo.Version,
			Elevated:         utils.IsElevated(),
			PasswordProvided: result.PasswordProvided,
		},
		Evaluation: statusJSONEvaluation{
			DetectedState:          detectedStateKey(result),
			SelectedCheckSet:       result.SelectedCheckSet,
			PasswordContext:        passwordContext(result),
			OverallResult:          overallResult(result),
			OverallStatus:          strings.TrimSuffix(summaryText, "."),
			TotalChecks:            len(checks),
			Passed:                 stats.passed,
			Warned:                 stats.warned,
			Failed:                 stats.failed,
			Skipped:                stats.skipped,
			Unavailable:            stats.unavailable,
			PartialEvaluation:      result.PartialEvaluation,
			PartialReason:          result.PartialReason,
			ReadyToProvision:       result.ReadyToProvision,
			ManageableInProduction: result.ManageableInProduction,
		},
		Checks: jsonChecks(checks),
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal status JSON: %w", err)
	}

	fmt.Fprintln(w, string(data))

	return nil
}
