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
	// LastError is the exit-code error derived from the structured Error block of the
	// final RPS `error` message, or from a failed component of a `success` message. Nil when
	// everything succeeded, and nil for older RPS releases that send neither (legacy
	// behavior: the process still exits 0).
	LastError error
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
	log.Tracef("  <- Raw message: %s", string(message))

	activation := Message{}

	err := json.Unmarshal(message, &activation)
	if err != nil {
		log.Println(err)

		return nil
	}

	log.Debugf("  <- Method: %s, Status: %s", activation.Method, activation.Status)

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
		err := json.Unmarshal([]byte(activation.Message), &statusMessage)
		if err != nil {
			log.Error(err)
			log.Info(sanitizeText(activation.Message))

			return nil
		}

		statusMessage.sanitize()
		logStatusMessage(statusMessage)

		// The flow succeeded, but a component that does not end the flow (network, TLS, CIRA) may
		// still have failed: report that through the exit code instead of exiting 0.
		if failed := firstFailedComponent(statusMessage.Components); failed != nil {
			amt.LastError = amt.exitCodeForFailure(failed)
		}

		return nil
	case "error":
		err := json.Unmarshal([]byte(activation.Message), &statusMessage)
		if err != nil {
			log.Error(sanitizeText(activation.Message))

			return nil
		}

		statusMessage.sanitize()

		if statusMessage.Error == nil {
			// Older RPS without the structured failure: legacy single-line error.
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

		log.Error(formatProvisioningError(failure))

		amt.LastError = amt.exitCodeForFailure(failure)

		return nil
	}

	msgPayload, err := base64.StdEncoding.DecodeString(activation.Payload)
	if err != nil {
		log.Error("unable to decode base64 payload from RPS")
	}

	log.Trace("PAYLOAD:" + string(msgPayload))

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
		{"Wired Network", c.WiredNetwork, true},
		{"Wireless Network", c.WirelessNetwork, true},
		{componentTLS, c.TLS, true},
		{"CIRA Proxy", c.CIRAProxy, true},
		{"CIRA Connection", c.CIRAConnection, true},
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
	} else {
		log.Info(line)
	}
}

// failureSuffix renders the structured failure detail RPS attaches to a failed component
// (code, step, AMT return value) as " [CODE @ STEP, ReturnValue N]". Empty when the RPS
// release did not send any of them, so legacy rows are unchanged.
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

	if result.AmtReturnValue != nil {
		parts = append(parts, fmt.Sprintf("ReturnValue %d", *result.AmtReturnValue))
	}

	if len(parts) == 0 {
		return ""
	}

	return " [" + strings.Join(parts, ", ") + "]"
}

// componentTLS is the TLS component name: both its summary label and its name on the wire.
const componentTLS = "TLS"

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
		for _, result := range []*ComponentResult{c.Activation, c.WiredNetwork, c.WirelessNetwork, c.TLS, c.CIRAProxy, c.CIRAConnection} {
			if result == nil {
				continue
			}

			result.Result = sanitizeText(result.Result)
			result.Mode = sanitizeText(result.Mode)
			result.Details = sanitizeText(result.Details)
			result.Code = sanitizeText(result.Code)
			result.Step = sanitizeText(result.Step)
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
func firstFailedComponent(c *ComponentResults) *ProvisioningError {
	if c == nil {
		return nil
	}

	components := []struct {
		name   string
		result *ComponentResult
	}{
		{"WiredNetwork", c.WiredNetwork},
		{"WirelessNetwork", c.WirelessNetwork},
		{componentTLS, c.TLS},
		{"CIRAProxy", c.CIRAProxy},
		{"CIRAConnection", c.CIRAConnection},
	}

	for _, comp := range components {
		if comp.result != nil && comp.result.Result == ComponentResultFailure {
			return &ProvisioningError{Code: comp.result.Code, Component: comp.name, Step: comp.result.Step, Reason: comp.result.Details}
		}
	}

	return nil
}

// failureLabel names the flow that failed, so a deactivation or maintenance failure is not
// reported as a provisioning failure.
func failureLabel(component string) string {
	switch component {
	case "Deactivation":
		return "Deactivation failed"
	case "Maintenance":
		return "Maintenance failed"
	default:
		return "Provisioning failed"
	}
}

// formatProvisioningError renders the final structured failure as one readable line:
//
//	Provisioning failed [WirelessNetwork/ADD_WIFI_SETTINGS] AMT_PT_UNSUPPORTED: <reason> (AMT_WiFiPortConfigurationService.AddWiFiSettings; AMT ReturnValue 2066)
func formatProvisioningError(e *ProvisioningError) string {
	location := e.Component
	if e.Step != "" {
		location += "/" + e.Step
	}

	line := fmt.Sprintf("%s [%s] %s: %s", failureLabel(e.Component), location, e.Code, e.Reason)

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
	case "WiredNetwork":
		code = utils.NetworkConfigurationFailed
	case "WirelessNetwork":
		code = utils.WiFiConfigurationFailed
	case componentTLS:
		code = utils.TLSConfigurationFailed
	case "CIRAProxy", "CIRAConnection":
		code = utils.CIRAConfigurationFailed
	case "Features":
		code = utils.AMTFeaturesConfigurationFailed
	case "Unconfiguration":
		code = utils.DeleteConfigsFailed
	case "Deactivation":
		code = utils.DeactivationFailed
	case "Maintenance", "TimeSync":
		code = amt.maintenanceExitCode(e.Component)
	default:
		code = utils.GenericFailure
	}

	code.Details = e.Code

	return code
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
	if component == "TimeSync" {
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
