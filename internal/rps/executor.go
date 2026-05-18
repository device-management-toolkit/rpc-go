/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// handshakeTimeout bounds the wait for APF_CHANNEL_OPEN_CONFIRMATION so a Listen
// goroutine that exits before signaling Done() can't deadlock the activation loop.
var handshakeTimeout = (utils.HeciReadTimeout + 15) * time.Second

// maxPortSwitchDelaySeconds caps the AMT TLS-restart wait that RPS asks for via
// the port_switch payload. The server-supplied value is clamped to this maximum
// to bound how long the activation loop can be blocked on a (possibly hostile
// or buggy) server-controlled delay.
const maxPortSwitchDelaySeconds = 60

type Executor struct {
	server          AMTActivationServer
	localManagement lm.LocalMananger
	isLME           bool
	payload         Payload
	data            chan []byte
	errors          chan error
	waitGroup       *sync.WaitGroup
	lastError       error
	// TLS tunnel state
	tlsTunnelActive  bool // true after port switch; gates tunnel behaviors
	lmConnected      bool // tracks if LMS connection is active (for TLS tunnel persistence)
	switchedToTunnel bool // true once we are in plain-TCP tunnel mode (after port_switch or auto-switch on tls_data)
}
type ExecutorConfig struct {
	URL              string
	Proxy            string
	LocalTlsEnforced bool
	SkipAmtCertCheck bool
	ControlMode      int
	SkipCertCheck    bool
	TLSTunnel        bool
}

func NewExecutor(config ExecutorConfig) (Executor, error) {
	// these are closed in the close function for each lm implementation
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	port := utils.LMSPort
	if config.LocalTlsEnforced {
		port = utils.LMSTLSPort
	}

	lmsConn := lm.NewLMSConnection(utils.LMSAddress, port, config.LocalTlsEnforced, lmDataChannel, lmErrorChannel, config.ControlMode, config.SkipAmtCertCheck)
	if config.LocalTlsEnforced {
		// When TLS is enforced, use plain-TCP tunnel mode from the start.
		// rpc-go forwards raw bytes; the TLS session is managed end-to-end by
		// RPS's TLSTunnelManager. Sending our own TLS layer on top would cause
		// TLS-in-TLS which AMT rejects. This also avoids needing an autoSwitch
		// when the first tls_data message arrives.
		lmsConn.SetTLSTunnelMode(true)
	}

	client := Executor{
		server:           NewAMTActivationServer(config.URL, config.Proxy),
		localManagement:  lmsConn,
		data:             lmDataChannel,
		errors:           lmErrorChannel,
		waitGroup:        &sync.WaitGroup{},
		tlsTunnelActive:  config.LocalTlsEnforced,
		switchedToTunnel: config.LocalTlsEnforced, // already in plain-TCP tunnel mode from the start
	}

	// TEST CONNECTION TO SEE IF LMS EXISTS
	err := client.localManagement.Connect()
	if err != nil {
		if config.LocalTlsEnforced {
			return client, utils.LMSConnectionFailed
		}
		// client.localManagement.Close()
		log.Trace("LMS not running.  Using LME Connection\n")

		client.localManagement = lm.NewLMEConnection(lmDataChannel, lmErrorChannel, client.waitGroup)
		client.isLME = true
		client.localManagement.Initialize()
	} else {
		log.Trace("Using existing LMS\n")
		client.localManagement.Close()
	}

	err = client.server.Connect(config.SkipCertCheck)
	if err != nil {
		// TODO: should the connection be closed?
		// client.localManagement.Close()
		log.Error("error connecting to RPS")
	}

	return client, err
}

// MakeItSo uses a pointer receiver because it updates executor state (lastError)
// across the activation loop.
func (e *Executor) MakeItSo(messageRequest Message) error {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	rpsDataChannel := e.server.Listen()

	log.Debug("sending activation request to RPS")

	err := e.server.Send(messageRequest)
	if err != nil {
		log.Error(err.Error())

		return fmt.Errorf("failed to send activation request: %w", err)
	}

	defer e.localManagement.Close()

	for {
		select {
		case dataFromServer, ok := <-rpsDataChannel:
			if !ok {
				e.lastError = errors.New("rps connection closed unexpectedly")

				return e.lastError
			}

			shallIReturn := e.HandleDataFromRPS(dataFromServer)
			if shallIReturn { // quits the loop -- we're either done or reached a point where we need to stop
				return e.lastError
			}
		case <-interrupt:
			e.HandleInterrupt()

			return fmt.Errorf("interrupted by user")
		}
	}
}

func (e Executor) HandleInterrupt() {
	log.Info("interrupt")

	// Cleanly close the connection by sending a close message and then
	// waiting (with timeout) for the server to close the connection.
	// err := e.localManagement.Close()
	// if err != nil {
	// 	log.Error("Connection close failed", err)
	// 	return
	// }
	err := e.server.Close()
	if err != nil {
		log.Error("Connection close failed", err)

		return
	}
}

// HandleDataFromRPS processes one RPS message and returns true when activation should stop.
func (e *Executor) HandleDataFromRPS(dataFromServer []byte) bool {
	msg, err := e.server.ProcessMessage(dataFromServer)
	if err != nil {
		e.lastError = err

		return true
	}

	if msg.Terminal {
		log.Info("RPS sent terminal message (success/error), ending activation flow")

		return true
	}

	switch msg.Method {
	case "heartbeat":
		return false
	case MethodPortSwitch:
		if err := e.handlePortSwitch(string(msg.Payload)); err != nil {
			log.Error("Port switch failed: ", err)
			e.lastError = fmt.Errorf("port switch failed: %w", err)

			return true
		}

		return false
	case MethodTLSData:
		// RPS v2.x sends tls_data directly without a prior port_switch.
		// Auto-switch to plain-TCP tunnel mode so raw TLS bytes pass through
		// unmodified instead of being wrapped in another TLS layer (TLS-in-TLS).
		if e.tlsTunnelActive && !e.switchedToTunnel {
			e.autoSwitchToRawTunnel()
		}
	}

	// Detect TLS ClientHello - close existing connection so firmware can renegotiate
	if len(msg.Payload) >= 6 && msg.Payload[0] == 0x16 && msg.Payload[5] == 0x01 && e.lmConnected {
		log.Debug("TLS ClientHello detected, closing existing connection for new handshake")
		e.localManagement.Close()
		e.lmConnected = false
	}

	log.Debug("RPS sent activation data, processing...")

	isSilentCloseCommand := isAdminSetupRequest(msg.Payload)

	// Set up connection and listener based on transport mode
	if e.isLME {
		if err := e.prepareLME(); err != nil {
			e.lastError = err

			return true
		}
	} else if e.tlsTunnelActive {
		if err := e.prepareLMSTunnel(); err != nil {
			e.lastError = err

			return true
		}
	} else {
		if err := e.prepareLMS(); err != nil {
			e.lastError = err

			return true
		}

		defer func() {
			e.localManagement.Close()
			e.lmConnected = false
		}()
	}

	// Unified send across all transport modes
	err = e.localManagement.Send(msg.Payload)
	if err != nil {
		e.lastError = fmt.Errorf("failed to send payload to LME/LMS: %w", err)
		log.Error(err)

		return true
	}

	// Use longer timeout for TLS tunnel mode (AMT may take 60+ seconds for TLS restart)
	responseTimeout := utils.AMTResponseTimeout * time.Second
	if e.tlsTunnelActive {
		responseTimeout = 90 * time.Second
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), responseTimeout)
	defer cancel()

	for {
		select {
		case dataFromLM := <-e.data:
			if len(dataFromLM) == 0 {
				// Silent-close commands: AMT closes the LMS connection without sending a response.
				// Verify provisioning actually succeeded via HECI GetControlMode before synthesizing
				// a success response, so we don't lie to RPS if the device is still unprovisioned.
				if isSilentCloseCommand {
					// In TLS tunnel mode, do not synthesize a plaintext SOAP response as tls_data.
					// RPS expects tunnel bytes here; injecting XML can desynchronize the tunnel
					// and lead to idle timeout/EOF. Let the flow continue to the next RPS step.
					if e.tlsTunnelActive {
						log.Debug("AdminSetup silent close in TLS tunnel mode; skipping synthetic fallback response")

						return false
					}

					if !e.isLME {
						// LMS path: HECI is free — verify control mode.
						controlMode, cmErr := amt.NewAMTCommand().GetControlMode()
						if cmErr != nil {
							e.lastError = fmt.Errorf("AdminSetup silent-close: GetControlMode failed, cannot confirm provisioning: %w", cmErr)
							log.Error(e.lastError)

							return true
						}

						if controlMode == 0 {
							e.lastError = errors.New("AdminSetup silent-close: device still unprovisioned (control mode 0) after silent close")
							log.Error(e.lastError)

							return true
						}

						log.Warnf("AdminSetup: verified provisioned (control mode %d); sending synthetic success response", controlMode)
					} else {
						// LME path: HECI is in use by the APF tunnel — skip verification.
						log.Warn("AdminSetup: AMT closed connection without responding (expected, LME path); sending synthetic success response")
					}

					fallbackResponse := buildAdminSetupFallbackResponse(msg.Payload)
					e.HandleDataFromLM(fallbackResponse)

					return false
				}

				if e.tlsTunnelActive {
					log.Warn("Empty response from LMS - sending connection_reset")
					e.localManagement.Close()
					e.lmConnected = false

					resetMsg := e.payload.CreateMessageResponse([]byte("connection_closed"), MethodConnectionReset)
					e.server.Send(resetMsg)
				}

				return false
			}

			log.Debug("Received response from LME/LMS, forwarding to RPS")

			if isSilentCloseCommand {
				if rv, ok := extractSetupReturnValue(dataFromLM); ok && rv != 0 {
					e.lastError = formatSetupReturnValueError(rv)
					log.Error(e.lastError)
					e.HandleDataFromLM(dataFromLM)

					return true
				}
			}

			e.HandleDataFromLM(dataFromLM)
			log.Debug("Response sent to RPS, waiting for next RPS message")

			if e.isLME {
				e.waitGroup.Wait()
			}

			if !e.tlsTunnelActive {
				e.localManagement.Close()
				e.lmConnected = false
			}

			return false
		case errFromLMS := <-e.errors:
			if errFromLMS != nil {
				// HECI read timeout is expected while polling for data.
				if errors.Is(errFromLMS, heci.ErrReadTimeout) {
					log.Debug("heci read timeout (normal driver timeout, not an error)")

					continue
				}

				// TLS 1.3 has normal handshake rounds where LMS emits no immediate
				// bytes (e.g. immediately after our client Finished). The LMS
				// Listen goroutine surfaces those via ErrLMSReadTimeoutNoData; in
				// TLS-tunnel mode treat them as a benign continuation so the
				// connection and AMT-side TLS state stay alive and the next
				// queued tls_data RPS message rides the same socket. Outside
				// TLS-tunnel mode the historical fatal handling still applies.
				if e.tlsTunnelActive && errors.Is(errFromLMS, lm.ErrLMSReadTimeoutNoData) {
					log.Trace("No LMS data before read timeout for this TLS round-trip; continuing without connection_reset")

					return false
				}

				log.Error("LMS error: ", errFromLMS)

				if e.tlsTunnelActive {
					e.localManagement.Close()
					e.lmConnected = false

					resetMsg := e.payload.CreateMessageResponse([]byte("lms_error"), MethodConnectionReset)
					e.server.Send(resetMsg)

					return false
				}

				e.lastError = fmt.Errorf("LME/LMS error: %w", errFromLMS)

				return true
			}
		case <-timeoutCtx.Done():
			// Timeout waiting for response from AMT/LME
			// This indicates AMT is not responding - treat as an error
			log.Error("Timeout waiting for LME response - AMT not responding")

			e.lastError = fmt.Errorf("timeout waiting for AMT response after %v", responseTimeout)

			return true
		}
	}
}

// prepareLME opens a fresh APF channel and waits (with bounded timeout) for
// AMT's CHANNEL_OPEN_CONFIRMATION before sending request data. AMT closes the
// channel after each response, so each request needs its own channel/Listen.
func (e *Executor) prepareLME() error {
	log.Debug("LME: Opening new APF channel for this request")

	// Fresh handshake WaitGroup per request: if a prior Listen exited without
	// signaling Done(), the old WG is abandoned rather than deadlocking this one.
	handshake := e.resetHandshake()

	err := e.localManagement.Connect()
	if err != nil {
		return fmt.Errorf("failed to open LME channel: %w", err)
	}

	go e.localManagement.Listen()

	// Bounded wait so a Listen goroutine that exits early on a HECI error
	// can't block this loop forever. OPEN_FAILURE also signals Done().
	handshakeDone := make(chan struct{})

	go func() {
		handshake.Wait()
		close(handshakeDone)
	}()

	select {
	case <-handshakeDone:
		log.Trace("Channel open confirmation received")
	case errFromLMS := <-e.errors:
		if errFromLMS != nil {
			return fmt.Errorf("LME error during channel open: %w", errFromLMS)
		}
	case <-time.After(handshakeTimeout):
		return fmt.Errorf("timed out waiting for APF channel open after %s", handshakeTimeout)
	}

	return nil
}

// resetHandshake installs a fresh WaitGroup on the LME session so each request
// starts from a known-zero counter; a stale Done() from an abandoned Listen
// can no longer race the current attempt's handshake wait.
func (e *Executor) resetHandshake() *sync.WaitGroup {
	wg := &sync.WaitGroup{}

	if lmec, ok := e.localManagement.(*lm.LMEConnection); ok && lmec.Session != nil {
		lmec.Session.WaitGroup = wg
	}

	e.waitGroup = wg

	return wg
}

// prepareLMSTunnel ensures the persistent tunnel connection is ready and starts a listener.
func (e *Executor) prepareLMSTunnel() error {
	if !e.lmConnected {
		err := e.localManagement.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect to LMS: %w", err)
		}

		e.lmConnected = true
	}

	go e.localManagement.Listen()

	return nil
}

// prepareLMS opens a fresh LMS connection and starts a listener (non-tunnel mode).
func (e *Executor) prepareLMS() error {
	err := e.localManagement.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to LMS: %w", err)
	}

	go e.localManagement.Listen()

	return nil
}

func (e *Executor) handlePortSwitch(jsonData string) error {
	var psPayload PortSwitchPayload
	if err := json.Unmarshal([]byte(jsonData), &psPayload); err != nil {
		return err
	}

	// Clamp the server-supplied delay so a hostile or buggy RPS can't block
	// the activation loop indefinitely.
	delaySeconds := psPayload.Delay
	if delaySeconds < 0 {
		delaySeconds = 0
	}

	if delaySeconds > maxPortSwitchDelaySeconds {
		log.Warnf("Port switch: server-requested delay %ds exceeds max %ds; clamping", delaySeconds, maxPortSwitchDelaySeconds)
		delaySeconds = maxPortSwitchDelaySeconds
	}

	log.Infof("Port switch: closing LMS connection, waiting %ds for AMT TLS restart", delaySeconds)

	// Close existing LMS connection
	e.localManagement.Close()
	e.lmConnected = false

	// Wait for AMT to restart its TLS subsystem. Use a cancellable wait so a
	// user interrupt (Ctrl+C / SIGTERM) can abort the activation loop promptly
	// instead of being delayed by the full sleep.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	timer := time.NewTimer(time.Duration(delaySeconds) * time.Second)

	select {
	case <-timer.C:
	case <-sigCh:
		timer.Stop()
		signal.Stop(sigCh)

		return fmt.Errorf("port switch wait interrupted")
	}

	signal.Stop(sigCh)

	// Create new LMS connection channels
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	// Create new plain TCP LMS connection on the TLS port.
	// rpc-go only passes raw bytes here — the actual TLS handshake is handled
	// by RPS's TLSTunnelManager through the WebSocket tunnel.
	newLM := lm.NewLMSConnection(
		utils.LMSAddress,
		psPayload.Port,
		false, // useTls must remain false here: RPS handles TLS, rpc-go forwards raw tunnel bytes
		lmDataChannel,
		lmErrorChannel,
		0,     // controlMode not needed for port switch
		false, // skipCertCheck not relevant — no TLS at this layer
	)
	newLM.SetTLSTunnelMode(true)

	// Test connection with retries
	maxRetries := 5

	var connectErr error

	for i := 0; i < maxRetries; i++ {
		connectErr = newLM.Connect()
		if connectErr == nil {
			break
		}

		log.Warnf("Port switch: LMS connect attempt %d/%d failed: %v", i+1, maxRetries, connectErr)
		time.Sleep(5 * time.Second)
	}

	if connectErr != nil {
		return connectErr
	}

	// Replace the LMS connection
	e.localManagement = newLM
	e.data = lmDataChannel
	e.errors = lmErrorChannel
	e.lmConnected = true
	e.tlsTunnelActive = true
	e.localManagement.Close() // Close test connection, will reconnect on next message
	e.lmConnected = false

	log.Info("Port switch: successfully switched to port ", psPayload.Port)

	// Send port_switch_ack back to RPS
	ackMsg := e.payload.CreateMessageResponse([]byte("ok"), MethodPortSwitchAck)
	if err := e.server.Send(ackMsg); err != nil {
		return err
	}

	log.Info("Port switch: sent port_switch_ack to RPS")

	e.switchedToTunnel = true

	return nil
}

// autoSwitchToRawTunnel switches the LMS connection from TLS mode to plain-TCP
// tunnel mode. This is needed when RPS (v2.x protocol) sends tls_data directly
// without a prior port_switch message. In raw-tunnel mode rpc-go forwards the
// bytes as-is; the TLS handshake is between RPS's TLSTunnelManager and AMT.
func (e *Executor) autoSwitchToRawTunnel() {
	log.Debug("Auto-switching to plain-TCP tunnel mode (tls_data received without prior port_switch)")

	// Close the existing TLS connection to LMS.
	e.localManagement.Close()
	e.lmConnected = false

	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	// Plain TCP to the LMS TLS port — no TLS wrapping at our level.
	// RPS's TLSTunnelManager owns the TLS session end-to-end.
	newLM := lm.NewLMSConnection(
		utils.LMSAddress,
		utils.LMSTLSPort,
		false, // useTls=false: raw byte forwarding, not TLS client
		lmDataChannel,
		lmErrorChannel,
		0,
		false,
	)
	newLM.SetTLSTunnelMode(true)

	e.localManagement = newLM
	e.data = lmDataChannel
	e.errors = lmErrorChannel
	e.switchedToTunnel = true

	log.Info("Auto-switched to plain-TCP tunnel mode on port ", utils.LMSTLSPort)
}

func isAdminSetupRequest(payload []byte) bool {
	// Commands that close the LMS connection without sending HTTP response body:
	// - AdminSetup (provisioning): IPS_HostBasedSetupService/AdminSetup
	// - Unprovision (deactivation): AMT_SetupAndConfigurationService/Unprovision
	// - Delete (certificate cleanup): /transfer/Delete
	return bytes.Contains(payload, []byte("IPS_HostBasedSetupService/AdminSetup")) ||
		bytes.Contains(payload, []byte("<h:AdminSetup_INPUT")) ||
		bytes.Contains(payload, []byte("AMT_SetupAndConfigurationService/Unprovision")) ||
		bytes.Contains(payload, []byte("<h:Unprovision_INPUT")) ||
		bytes.Contains(payload, []byte("/transfer/Delete"))
}

func buildAdminSetupFallbackResponse(requestPayload []byte) []byte {
	return buildSetupServiceSuccessResponse(requestPayload, "AdminSetup", "AdminSetup_OUTPUT")
}

func buildSetupServiceSuccessResponse(requestPayload []byte, actionName, outputTag string) []byte {
	messageID := extractMessageID(requestPayload)
	soapBody := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
		"<a:Envelope xmlns:a=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:b=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:c=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:g=\"http://intel.com/wbem/wscim/1/ips-schema/1/IPS_HostBasedSetupService\">" +
		"<a:Header>" +
		"<b:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</b:To>" +
		"<b:RelatesTo>" + messageID + "</b:RelatesTo>" +
		"<b:Action a:mustUnderstand=\"true\">http://intel.com/wbem/wscim/1/ips-schema/1/IPS_HostBasedSetupService/" + actionName + "Response</b:Action>" +
		"<b:MessageID>uuid:00000000-8086-8086-8086-000000000000</b:MessageID>" +
		"<c:ResourceURI>http://intel.com/wbem/wscim/1/ips-schema/1/IPS_HostBasedSetupService</c:ResourceURI>" +
		"</a:Header>" +
		"<a:Body><g:" + outputTag + "><g:ReturnValue>0</g:ReturnValue></g:" + outputTag + "></a:Body>" +
		"</a:Envelope>"

	chunkLen := fmt.Sprintf("%X", len(soapBody))

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		chunkLen + "\r\n" +
		soapBody + "\r\n" +
		"0\r\n\r\n"

	return []byte(response)
}

func extractMessageID(payload []byte) string {
	messageID, ok := extractTagValue(payload, "<a:MessageID>", "</a:MessageID>")
	if !ok {
		return "0"
	}

	return messageID
}

func (e *Executor) HandleDataFromLM(data []byte) {
	if len(data) > 0 {
		method := "response"
		if e.tlsTunnelActive {
			method = MethodTLSData
		}

		err := e.server.Send(e.payload.CreateMessageResponse(data, method))
		if err != nil {
			log.Error(err)
		}
	}
}

func extractSetupReturnValue(response []byte) (int, bool) {
	resp := string(response)
	if !strings.Contains(resp, "Setup_OUTPUT") && !strings.Contains(resp, "AdminSetup_OUTPUT") {
		return 0, false
	}

	valueStr, ok := extractTagValue(response, "<g:ReturnValue>", "</g:ReturnValue>")
	if !ok {
		return 0, false
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return 0, false
	}

	return value, true
}

func extractTagValue(payload []byte, openTag, closeTag string) (string, bool) {
	text := string(payload)

	start := strings.Index(text, openTag)
	if start == -1 {
		return "", false
	}

	start += len(openTag)

	end := strings.Index(text[start:], closeTag)
	if end == -1 {
		return "", false
	}

	value := strings.TrimSpace(text[start : start+end])
	if value == "" {
		return "", false
	}

	return value, true
}

func formatSetupReturnValueError(rv int) error {
	if rv == 1 {
		return fmt.Errorf("AMT Setup failed with ReturnValue=1 (NotSupported): device likely has CCM disabled or profile is incompatible")
	}

	return fmt.Errorf("AMT Setup failed with ReturnValue=%d (device/profile does not support this provisioning flow)", rv)
}
