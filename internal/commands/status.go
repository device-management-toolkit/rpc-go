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
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
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

// checkState models the outcome of a single readiness check.
type checkState int

const (
	checkPass checkState = iota // requirement satisfied (green)
	checkWarn                   // not satisfied, but not fatal on its own (yellow)
	checkFail                   // requirement not satisfied (red)
	checkSkip                   // not applicable / not evaluated (dim)
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
	MEIDriverPresent bool   `json:"meiDriverPresent"`
	ControlMode      string `json:"controlMode,omitempty"`
	AlreadyActivated bool   `json:"alreadyActivated"`
	LMSInstalled     bool   `json:"lmsInstalled"`
	WiredLinkUp      bool   `json:"wiredLinkUp"`
	WirelessLinkUp   bool   `json:"wirelessLinkUp"`
	Host             string `json:"host,omitempty"`
	HostReachable    *bool  `json:"hostReachable,omitempty"`
	ReadyToProvision bool   `json:"readyToProvision"`
}

// StatusCmd reports whether the local device is ready to be provisioned.
type StatusCmd struct {
	AMTBaseCmd

	Host string `help:"Host[:port] to test network reachability against (default port 443)" name:"host"`
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

	result, checks := cmd.gather(ctx)

	if ctx.JsonOutput {
		if err := outputStatusJSON(os.Stdout, result); err != nil {
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

// gather runs every readiness check and computes the overall verdict.
func (cmd *StatusCmd) gather(ctx *Context) (StatusResult, []healthCheck) {
	var result StatusResult

	checks := []healthCheck{
		cmd.meiCheck(&result),
		cmd.controlModeCheck(&result),
		cmd.lmsCheck(&result),
		cmd.linkCheck(ctx, false, &result.WiredLinkUp),
		cmd.linkCheck(ctx, true, &result.WirelessLinkUp),
	}

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

// controlModeCheck reports the activation state. Pre-provisioning (control
// mode 0) is the green, ready-to-activate state; an already-activated device
// (CCM/ACM) is flagged so the verdict reports it rather than "ready".
func (cmd *StatusCmd) controlModeCheck(result *StatusResult) healthCheck {
	const label = "Control mode"

	if !cmd.HECIAvailable {
		return healthCheck{label, checkSkip, "unavailable (MEI driver required)"}
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
func (cmd *StatusCmd) linkCheck(ctx *Context, wireless bool, up *bool) healthCheck {
	label := "Wired network link"
	if wireless {
		label = "Wireless network link"
	}

	if !cmd.HECIAvailable || ctx.AMTCommand == nil {
		return healthCheck{label, checkSkip, "unavailable (MEI driver required)"}
	}

	settings, err := ctx.AMTCommand.GetLANInterfaceSettings(wireless)
	if err != nil {
		log.Debugf("failed to read LAN interface settings (wireless=%v): %v", wireless, err)

		return healthCheck{label, checkWarn, "could not read link status"}
	}

	if !strings.EqualFold(settings.LinkStatus, linkStatusUp) {
		return healthCheck{label, checkWarn, linkDisconnected}
	}

	*up = true

	detail := linkConnected
	if settings.IPAddress != "" && settings.IPAddress != zeroIP {
		detail = linkConnected + " (" + settings.IPAddress + ")"
	}

	return healthCheck{label, checkPass, detail}
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

// renderStatus writes the human-readable readiness report. Labels are padded
// to a common width (measured, not forced via lipgloss Width which would wrap
// long labels) so the detail column lines up.
func renderStatus(w io.Writer, result StatusResult, checks []healthCheck) {
	var b strings.Builder

	b.WriteString(renderInfoHeader("AMT Provisioning Readiness"))

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

	if !result.LMSInstalled {
		b.WriteString("\n" + infoIndent + infoYellowStyle.Render("LMS features not available, e.g.:") + "\n")

		for _, feature := range lmsDependentFeatures {
			b.WriteString(infoIndent + infoIndent + infoDimStyle.Render("• "+feature) + "\n")
		}
	}

	b.WriteString("\n")

	fmt.Fprint(w, b.String())
}

// Verdict summary messages — single source of truth, asserted by tests.
const (
	verdictNoAMT           = "Device does not have AMT"
	verdictUnknownPriv     = "AMT status unknown (run as administrator)"
	verdictAlreadyActive   = "AMT device is already activated"
	verdictCannotProvision = "AMT cannot be provisioned"
	verdictNotManaged      = "AMT can be provisioned, but not managed"
	verdictReady           = "AMT device ready to be provisioned"
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

// outputStatusJSON writes the machine-readable status result.
func outputStatusJSON(w io.Writer, result StatusResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal status JSON: %w", err)
	}

	fmt.Fprintln(w, string(data))

	return nil
}
