/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// AMTActivationServer struct represents the connection to RPS
type AMTActivationServer struct {
	URL   string
	Conn  *websocket.Conn
	flags *flags.Flags
	// LastError is the exit-code error for the run. Any RPS `error` message sets it, including
	// one from an older RPS release with no structured Error block (the command being run picks
	// the exit code); the Error block, when present, refines it. A failed component of a
	// `success` message sets it too. Nil only when everything succeeded.
	LastError error
	// Completed is true once RPS has sent its final `success` message. A session that ends with
	// neither Completed nor LastError set stopped early (RPS went away, the run was interrupted,
	// a frame could not be read) and must not exit 0.
	Completed bool
}

func ExecuteCommand(flags *flags.Flags) error {
	setCommandMethod(flags)

	startMessage, err := PrepareInitialMessage(flags)
	if err != nil {
		return err
	}

	executor, err := NewExecutor(*flags)
	if err != nil {
		return err
	}

	return executor.MakeItSo(startMessage)
}

func setCommandMethod(flags *flags.Flags) {
	switch flags.Command {
	case utils.CommandActivate:
		flags.Command += " --profile " + flags.Profile
	case utils.CommandDeactivate:
		flags.Command += " --password " + flags.Password
	case utils.CommandMaintenance:
		flags.Command += " -password " + flags.Password

		task := flags.SubCommand
		if task == utils.SubCommandSyncClock {
			task = utils.SubCommandSyncTime
		}

		flags.Command += " --" + task
		if task == utils.SubCommandChangePassword && flags.StaticPassword != "" {
			flags.Command += " " + flags.StaticPassword
		}
	}

	if flags.Force {
		flags.Command += " -f"
	}
}

// TODO: suggest this be renamed to RemoteProvisioningService
func NewAMTActivationServer(flags *flags.Flags) AMTActivationServer {
	amtactivationserver := AMTActivationServer{
		URL:   flags.URL,
		flags: flags,
	}

	return amtactivationserver
}

func PrepareInitialMessage(flags *flags.Flags) (Message, error) {
	payload := NewPayload()

	return payload.CreateMessageRequest(*flags)
}

// Connect is used to connect to the RPS Server
func (amt *AMTActivationServer) Connect(skipCertCheck bool) error {
	log.Info("connecting to ", amt.URL)
	log.Debugf("TLS certificate verification: %s", map[bool]string{true: "DISABLED (InsecureSkipVerify=true)", false: "ENABLED"}[skipCertCheck])

	var err error

	websocketDialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipCertCheck,
		},
	}

	if amt.flags.Proxy != "" {
		// Parse the URL of the proxy.
		proxyURL, err := url.Parse(amt.flags.Proxy)
		if err != nil {
			panic(err)
		}

		websocketDialer.Proxy = func(*http.Request) (*url.URL, error) {
			return proxyURL, nil
		}
	} else {
		websocketDialer.Proxy = http.ProxyFromEnvironment
	}

	var resp *http.Response

	amt.Conn, resp, err = websocketDialer.Dial(amt.URL, nil)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
		}

		return err
	}

	log.Info("connected to ", amt.URL)

	return nil
}

// Close closes the connection to rps
func (amt *AMTActivationServer) Close() error {
	log.Info("closed RPS connection")

	err := amt.Conn.Close()
	if err != nil {
		return err
	}

	return nil
}

// Send is used for sending data to the RPS Server
func (amt *AMTActivationServer) Send(data Message) error {
	dataToSend, err := json.Marshal(data)
	if err != nil {
		log.Error("unable to marshal activationResponse to JSON")

		return err
	}

	log.Debug("sending message to RPS")
	log.Debugf("  -> Method: %s, Status: %s", data.Method, data.Status)
	log.Tracef("  -> Full message: %s", string(dataToSend))

	err = amt.Conn.WriteMessage(websocket.TextMessage, dataToSend)
	if err != nil {
		return err
	}

	return nil
}

// Listen is used for listening to responses from RPS
func (amt *AMTActivationServer) Listen() chan []byte {
	log.Debug("listening to RPS...")

	dataChannel := make(chan []byte)

	go func() {
		defer close(dataChannel)

		for {
			_, message, err := amt.Conn.ReadMessage()
			if err != nil {
				log.Error("error:", err)

				break
			}

			dataChannel <- message
		}
	}()

	return dataChannel
}

// ProcessMessage inspects RPS messages, decodes the base64 payload from the server and relays it to LMS
func (amt *AMTActivationServer) ProcessMessage(message []byte) []byte {
	log.Debug("received message from RPS")
	log.Tracef("  <- Raw message: %s", sanitizeText(string(message)))

	activation := Message{}

	err := json.Unmarshal(message, &activation)
	if err != nil {
		log.Println(err)

		return nil
	}

	log.Debugf("  <- Method: %s, Status: %s", sanitizeText(activation.Method), sanitizeText(activation.Status))

	if activation.Method == "heartbeat_request" {
		heartbeat, _ := amt.GenerateHeartbeatResponse(activation)

		return heartbeat
	}

	// Handle TLS tunnel data - decode and pass through to LMS
	if activation.Method == MethodTLSData {
		msgPayload, err := base64.StdEncoding.DecodeString(activation.Payload)
		if err != nil {
			log.Error("Failed to decode tls_data payload:", err)

			return nil
		}

		log.Debugf("TLS tunnel: passing through TLS data to LMS (%d bytes)", len(msgPayload))

		return msgPayload
	}

	// Handle port_switch - RPS is telling us to switch LMS connection to TLS
	if activation.Method == MethodPortSwitch {
		log.Info("Received port_switch from RPS")

		return []byte(PortSwitchSentinel + activation.Payload)
	}

	// Progress: log the message at info level, return a sentinel so the
	// executor loop stays alive without forwarding to LMS.
	if activation.Method == MethodProgress {
		log.Info(sanitizeText(activation.Message))

		return []byte(ProgressSentinel)
	}

	statusMessage := StatusMessage{}

	switch activation.Method {
	case "success":
		amt.Completed = true

		err := json.Unmarshal([]byte(activation.Message), &statusMessage)
		if err != nil {
			log.Error(err)
			log.Info(sanitizeText(activation.Message))

			return nil
		}

		statusMessage.sanitize()
		logStatusMessage(statusMessage)

		// The flow succeeded, but a component that does not end the flow (network, TLS, CIRA,
		// AMT features, unconfiguration) may still have failed: report that through the exit code
		// instead of exiting 0.
		if failed := firstFailedComponent(statusMessage.Components); failed != nil {
			amt.LastError = amt.exitCodeForFailure(failed)

			// One line with the component, step, code, reason and call, in the same format as a
			// failed flow, so the end of the log explains the exit code. Older RPS releases send
			// no code for a failed component: the row above is all there is to show.
			if failed.Code != "" {
				log.Error(formatProvisioningError(failed, amt.subCommand()))
			}
		}

		return nil
	case "error":
		// An error message always fails the run. The structured Error block, when present, only
		// refines which exit code is used.
		amt.LastError = amt.exitCodeForUnstructuredError()

		err := json.Unmarshal([]byte(activation.Message), &statusMessage)
		if err != nil {
			// Plain-text error, e.g. a failure RPS raises before its state machine starts.
			log.Error(sanitizeText(activation.Message))

			return nil
		}

		statusMessage.sanitize()

		if statusMessage.Error == nil {
			// Older RPS without the structured failure: legacy single-line error. A JSON
			// message with no Status would log an empty line, so show the message itself.
			if statusMessage.Status == "" {
				log.Error(sanitizeText(activation.Message))

				return nil
			}

			log.Error(statusMessage.Status)

			return nil
		}

		// Structured failure: per-component summary (when present), the flow's own status text,
		// then one line that names the failing component, step, code and reason, so the edge
		// shows where and why the flow failed without reading RPS logs.
		if statusMessage.Components != nil {
			logStatusMessage(statusMessage)
		}

		failure := statusMessage.Error

		// Status is the task-specific message (e.g. why a password change failed); keep it unless
		// the structured line already says the same thing.
		if statusMessage.Status != "" && statusMessage.Status != failure.Reason {
			log.Error(statusMessage.Status)
		}

		log.Error(formatProvisioningError(failure, amt.subCommand()))

		amt.LastError = amt.exitCodeForFailure(failure)

		return nil
	}

	msgPayload, err := base64.StdEncoding.DecodeString(activation.Payload)
	if err != nil {
		log.Error("unable to decode base64 payload from RPS")
	}

	log.Trace("PAYLOAD:" + sanitizeText(string(msgPayload)))

	return msgPayload
}

// logStatusMessage reports the activation result. When RPS provides the structured
// per-component breakdown (rps#2665) it is rendered as an aligned summary with a status
// glyph per component; otherwise the legacy flat status fields are logged for
// compatibility with older RPS releases.
func logStatusMessage(statusMessage StatusMessage) {
	c := statusMessage.Components
	if c == nil {
		// Older RPS without the structured breakdown: log the legacy flat fields.
		log.Info("Status: " + statusMessage.Status)
		log.Info("Network: " + statusMessage.Network)
		log.Info("CIRA: " + statusMessage.CIRAConnection)
		log.Info("TLS: " + statusMessage.TLSConfiguration)

		return
	}

	log.Info("Provisioning and Configuration Result : ")

	// Every component surfaces its own mode inline (e.g. Activation shows [ACM]).
	components := []struct {
		label    string
		result   *ComponentResult
		showMode bool
	}{
		{"Activation", c.Activation, true},
		{componentNetwork, c.Network, true},
		{"Wired Network", c.WiredNetwork, true},
		{"Wireless Network", c.WirelessNetwork, true},
		{componentTLS, c.TLS, true},
		{"CIRA Proxy", c.CIRAProxy, true},
		{"CIRA Connection", c.CIRAConnection, true},
		{"AMT Features", c.Features, true},
		{componentUnconfiguration, c.Unconfiguration, true},
	}

	// Align labels to the widest reportable component so the rows line up.
	width := 0

	for _, comp := range components {
		if reportableComponent(comp.result) && len(comp.label) > width {
			width = len(comp.label)
		}
	}

	for _, comp := range components {
		logComponentResult(comp.label, comp.result, comp.showMode, width)
	}
}

// reportableComponent reports whether a component belongs in the summary. RPS sends a
// NotApplicable entry for every component that was not part of the configuration (and omits
// components it never reported); both are dropped so the summary shows only the steps that ran.
func reportableComponent(result *ComponentResult) bool {
	return result != nil && result.Result != ComponentResultNotApplicable
}

// logComponentResult logs a single aligned component row, skipping components that are not
// reportable (unreported or NotApplicable). Failures are logged at error level so they stay visible.
func logComponentResult(label string, result *ComponentResult, showMode bool, width int) {
	if !reportableComponent(result) {
		return
	}

	// Row: two-space indent, then the padded "label:" so detail columns line up.
	line := fmt.Sprintf("  %-*s", width+1, label+":")

	// Append the mode inline as [Mode] (e.g. [ACM]) when the component carries one.
	detail := result.Details
	if showMode && result.Mode != "" {
		if detail != "" {
			detail += " "
		}

		detail += "[" + result.Mode + "]"
	}

	if detail != "" {
		line += " " + detail
	}

	if result.Result == ComponentResultFailure {
		line += failureSuffix(result)
		log.Error(line)

		// Second row: what the code means, so the cause is readable without the RPS logs.
		if explanation := failureExplanation(result); explanation != "" {
			log.Error(fmt.Sprintf("  %-*s %s", width+1, "", explanation))
		}
	} else {
		log.Info(line)
	}
}

// failureExplanation renders the description of a failed component's code, with the underlying
// error text when RPS sent one. Empty when RPS sent neither, or when it only repeats Details.
func failureExplanation(result *ComponentResult) string {
	explanation := result.Reason
	if explanation == result.Details {
		explanation = ""
	}

	if result.Detail != "" && result.Detail != result.Details {
		if explanation == "" {
			return result.Detail
		}

		explanation += " (" + result.Detail + ")"
	}

	return explanation
}

// failureSuffix renders the structured failure detail RPS attaches to a failed component
// (code, step, WSMAN call, AMT return value, HTTP status) as
// " [CODE @ STEP, Class.Method, ReturnValue N, HTTP N]". Empty when the RPS release did not send
// any of them, so legacy rows are unchanged.
func failureSuffix(result *ComponentResult) string {
	parts := []string{}

	code, step := result.Code, result.Step

	if code != "" {
		if step != "" {
			code += " @ " + step
		}

		parts = append(parts, code)
	} else if step != "" {
		parts = append(parts, "@ "+step)
	}

	if result.WsmanCall != "" {
		parts = append(parts, result.WsmanCall)
	}

	if result.AmtReturnValue != nil {
		parts = append(parts, fmt.Sprintf("ReturnValue %d", *result.AmtReturnValue))
	}

	if result.HttpStatus != nil {
		parts = append(parts, fmt.Sprintf("HTTP %d", *result.HttpStatus))
	}

	if len(parts) == 0 {
		return ""
	}

	return " [" + strings.Join(parts, ", ") + "]"
}

// componentTLS is the TLS component name: both its summary label and its name on the wire.
const componentTLS = "TLS"

// componentNetwork is the shared network setup component name: both its summary label and its
// name on the wire.
const componentNetwork = "Network"

// componentUnconfiguration is the unconfiguration component name: both its summary label and its
// name on the wire.
const componentUnconfiguration = "Unconfiguration"

// componentTimeSync is the clock sync component name on the wire: a step of activation, or the
// maintenance time-sync task.
const componentTimeSync = "TimeSync"

// sanitizeText replaces characters that change how a terminal or log viewer renders text
// received from RPS with spaces: control characters (escape sequences, forged log lines),
// format characters (bidirectional overrides, zero-width characters) and the Unicode line and
// paragraph separators.
func sanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return ' '
		}

		return r
	}, s)
}

// sanitize makes every server-supplied string of the status message safe to print, in place.
// It runs once, right after the message is parsed, so no later log line can skip it.
func (s *StatusMessage) sanitize() {
	s.Status = sanitizeText(s.Status)
	s.Network = sanitizeText(s.Network)
	s.CIRAConnection = sanitizeText(s.CIRAConnection)
	s.TLSConfiguration = sanitizeText(s.TLSConfiguration)

	if c := s.Components; c != nil {
		for _, result := range c.all() {
			if result == nil {
				continue
			}

			result.Result = sanitizeText(result.Result)
			result.Mode = sanitizeText(result.Mode)
			result.Details = sanitizeText(result.Details)
			result.Code = sanitizeText(result.Code)
			result.Step = sanitizeText(result.Step)
			result.Reason = sanitizeText(result.Reason)
			result.WsmanCall = sanitizeText(result.WsmanCall)
			result.Detail = sanitizeText(result.Detail)
		}
	}

	if e := s.Error; e != nil {
		e.Code = sanitizeText(e.Code)
		e.Component = sanitizeText(e.Component)
		e.Step = sanitizeText(e.Step)
		e.Reason = sanitizeText(e.Reason)
		e.WsmanCall = sanitizeText(e.WsmanCall)
		e.Detail = sanitizeText(e.Detail)
	}
}

// firstFailedComponent returns the first component of a successful flow that reported a failure,
// as a failure the exit-code mapping understands, or nil when every component succeeded.
// "First" is the order of the summary rows below, not the order RPS ran the steps (RPS does not
// send that). A process has one exit code, so when several components failed this one sets it;
// every failure is still shown in its own summary row.
func firstFailedComponent(c *ComponentResults) *ProvisioningError {
	if c == nil {
		return nil
	}

	components := []struct {
		name   string
		result *ComponentResult
	}{
		{componentNetwork, c.Network},
		{"WiredNetwork", c.WiredNetwork},
		{"WirelessNetwork", c.WirelessNetwork},
		{componentTLS, c.TLS},
		{"CIRAProxy", c.CIRAProxy},
		{"CIRAConnection", c.CIRAConnection},
		{"Features", c.Features},
		{componentUnconfiguration, c.Unconfiguration},
	}

	for _, comp := range components {
		if comp.result != nil && comp.result.Result == ComponentResultFailure {
			// Reason describes the code; older RPS releases send only the Details text.
			reason := comp.result.Reason
			if reason == "" {
				reason = comp.result.Details
			}

			return &ProvisioningError{
				Code:           comp.result.Code,
				Component:      comp.name,
				Step:           comp.result.Step,
				Reason:         reason,
				AmtReturnValue: comp.result.AmtReturnValue,
				HttpStatus:     comp.result.HttpStatus,
				WsmanCall:      comp.result.WsmanCall,
				Detail:         comp.result.Detail,
			}
		}
	}

	return nil
}

// failureLabel names the flow that failed, so a deactivation or maintenance failure is not
// reported as a provisioning failure. RPS reports maintenance time sync under the TimeSync
// component, so the active maintenance subcommand decides its label; during activation the
// same component is the clock step of provisioning.
func failureLabel(component, subCommand string) string {
	switch component {
	case "Deactivation":
		return "Deactivation failed"
	case "Maintenance":
		return "Maintenance failed"
	case componentTimeSync:
		if isMaintenanceSubCommand(subCommand) {
			return "Maintenance failed"
		}
	}

	return "Provisioning failed"
}

// isMaintenanceSubCommand reports whether the running subcommand is a maintenance task.
func isMaintenanceSubCommand(subCommand string) bool {
	switch subCommand {
	case utils.SubCommandSyncClock, utils.SubCommandSyncTime, utils.SubCommandSyncHostname,
		utils.SubCommandSyncIP, utils.SubCommandChangePassword, utils.SubCommandSyncDeviceInfo:
		return true
	}

	return false
}

// formatProvisioningError renders the final structured failure as one readable line:
//
//	Provisioning failed [WirelessNetwork/ADD_WIFI_SETTINGS] AMT_PT_UNSUPPORTED: <reason> (AMT_WiFiPortConfigurationService.AddWiFiSettings; AMT ReturnValue 2066)
func formatProvisioningError(e *ProvisioningError, subCommand string) string {
	location := e.Component
	if e.Step != "" {
		location += "/" + e.Step
	}

	line := fmt.Sprintf("%s [%s] %s: %s", failureLabel(e.Component, subCommand), location, e.Code, e.Reason)

	extras := []string{}
	if e.WsmanCall != "" {
		extras = append(extras, e.WsmanCall)
	}

	if e.AmtReturnValue != nil {
		extras = append(extras, fmt.Sprintf("AMT ReturnValue %d", *e.AmtReturnValue))
	}

	if e.HttpStatus != nil {
		extras = append(extras, fmt.Sprintf("HTTP %d", *e.HttpStatus))
	}

	if e.Detail != "" {
		extras = append(extras, e.Detail)
	}

	if len(extras) > 0 {
		line += " (" + strings.Join(extras, "; ") + ")"
	}

	return line
}

// exitCodeForFailure maps the failing component of a structured RPS failure to the existing
// rpc-go exit code family (100-199). Maintenance failures are mapped from the maintenance
// subcommand that was running, since RPS reports them all under the Maintenance component.
// Details carries only the catalog code: the full reason was already logged once by
// formatProvisioningError, so the exit line printed by handleErrorAndExit does not repeat it.
func (amt *AMTActivationServer) exitCodeForFailure(e *ProvisioningError) utils.CustomError {
	var code utils.CustomError

	switch e.Component {
	case "Activation":
		code = utils.ActivationFailed
	case componentNetwork:
		// The shared network setup that runs before RPS knows which interfaces the device has.
		code = utils.NetworkConfigurationFailed
	case "WiredNetwork":
		// Same code as a wired failure in local mode, as WirelessNetwork already is.
		code = utils.WiredConfigurationFailed
	case "WirelessNetwork":
		code = utils.WiFiConfigurationFailed
	case componentTLS:
		code = utils.TLSConfigurationFailed
	case "CIRAProxy", "CIRAConnection":
		code = utils.CIRAConfigurationFailed
	case "Features":
		code = utils.AMTFeaturesConfigurationFailed
	case componentUnconfiguration:
		code = utils.DeleteConfigsFailed
	case "Deactivation":
		code = utils.DeactivationFailed
	case "Maintenance", componentTimeSync:
		code = amt.maintenanceExitCode(e.Component)
	default:
		code = utils.GenericFailure
	}

	code.Details = e.Code

	return code
}

// exitCodeForUnstructuredError picks the exit code for an "error" message that carries no
// structured Error block (an older RPS, or a failure raised before the RPS state machine starts).
// The command being run names the flow that failed. setCommandMethod has already appended the
// command's arguments to flags.Command by now, so only its first word is the command itself.
func (amt *AMTActivationServer) exitCodeForUnstructuredError() utils.CustomError {
	command := ""

	if amt.flags != nil {
		if words := strings.Fields(amt.flags.Command); len(words) > 0 {
			command = words[0]
		}
	}

	switch command {
	case utils.CommandActivate:
		return utils.ActivationFailed
	case utils.CommandDeactivate:
		return utils.DeactivationFailed
	case utils.CommandMaintenance:
		return amt.maintenanceExitCode("Maintenance")
	}

	return utils.GenericFailure
}

// subCommand returns the subcommand of the current run, if any.
func (amt *AMTActivationServer) subCommand() string {
	if amt.flags != nil {
		return amt.flags.SubCommand
	}

	return ""
}

// maintenanceExitCode picks the maintenance exit code from the subcommand being run.
func (amt *AMTActivationServer) maintenanceExitCode(component string) utils.CustomError {
	subCommand := ""
	if amt.flags != nil {
		subCommand = amt.flags.SubCommand
	}

	switch subCommand {
	case utils.SubCommandSyncClock, utils.SubCommandSyncTime:
		return utils.SyncClockFailed
	case utils.SubCommandSyncHostname:
		return utils.SyncHostnameFailed
	case utils.SubCommandSyncIP:
		return utils.SyncIpFailed
	case utils.SubCommandChangePassword:
		return utils.ChangePasswordFailed
	case utils.SubCommandSyncDeviceInfo:
		return utils.SyncDeviceInfoFailed
	}

	// Not a maintenance run: a time sync failure here is the clock step of an activation flow.
	if component == componentTimeSync {
		return utils.ActivationFailed
	}

	return utils.GenericFailure
}

func (amt *AMTActivationServer) GenerateHeartbeatResponse(activation Message) ([]byte, error) {
	activation.Method = "heartbeat_response"
	activation.Status = "success"

	err := amt.Send(activation)
	if err != nil {
		log.Error("Heartbeat send failure")

		return nil, err
	}

	return []byte("heartbeat"), nil
}
