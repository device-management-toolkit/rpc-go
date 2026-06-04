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
	"sync"
	"syscall"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
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
// or buggy) server-controlled delay. Overridable via RPC_PORT_SWITCH_MAX_DELAY.
var maxPortSwitchDelaySeconds = envInt("RPC_PORT_SWITCH_MAX_DELAY", 60)

// extraPortSwitchDelaySeconds is added on top of the server-requested delay
// (after clamping). Useful when AMT's TLS subsystem needs more time than RPS
// expects to bind the freshly-committed server cert to port 16993; raise this
// if you see "Failed to establish TLS tunnel connection" errors immediately
// after port_switch. Overridable via RPC_PORT_SWITCH_EXTRA_DELAY.
var extraPortSwitchDelaySeconds = envInt("RPC_PORT_SWITCH_EXTRA_DELAY", 0)

// lmePostKeygenPause: AMT 18.x briefly drops the LME MEI client after
// GenerateKeyPair persists the new key; pausing here pre-empts an ENODEV on
// the next CHANNEL_OPEN that would otherwise cost ~6s re-handshake.
// Overridable (milliseconds) via RPC_LME_POST_KEYGEN_PAUSE_MS.
var lmePostKeygenPause = time.Duration(envInt("RPC_LME_POST_KEYGEN_PAUSE_MS", 750)) * time.Millisecond

const soapActionGenerateKeyPair = "AMT_PublicKeyManagementService/GenerateKeyPair"

// envInt returns the integer value of env var name, or def if unset/invalid.
func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		log.Warnf("ignoring invalid %s=%q: %v", name, v, err)

		return def
	}

	return n
}

// waitWithSignal sleeps for d but returns early with an error if SIGINT/SIGTERM
// arrives, so the activation loop can abort promptly on Ctrl+C rather than
// being held by a server-requested delay.
func waitWithSignal(d time.Duration) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	timer := time.NewTimer(d)

	select {
	case <-timer.C:
		return nil
	case sig := <-sigCh:
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		return fmt.Errorf("port-switch wait interrupted by %v", sig)
	}
}

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
	tlsTunnelActive bool // true after port switch; gates tunnel behaviors
	lmConnected     bool // tracks if LMS connection is active (for TLS tunnel persistence)
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

	client := Executor{
		server:          NewAMTActivationServer(config.URL, config.Proxy),
		localManagement: lm.NewLMSConnection(utils.LMSAddress, port, config.LocalTlsEnforced, lmDataChannel, lmErrorChannel, config.ControlMode, config.SkipAmtCertCheck),
		data:            lmDataChannel,
		errors:          lmErrorChannel,
		waitGroup:       &sync.WaitGroup{},
		tlsTunnelActive: config.LocalTlsEnforced,
	}

	// TEST CONNECTION TO SEE IF LMS EXISTS
	err := client.localManagement.Connect()
	if err != nil {
		log.Tracef("LMS dial failed (%v); falling back to LME (in-band HECI/APF)", err)

		lme := lm.NewLMEConnection(lmDataChannel, lmErrorChannel, client.waitGroup)
		// On TLS-enforced AMT the active local port is 16993; aim the first
		// CHANNEL_OPEN there so RPS doesn't have to issue a port_switch just
		// to get past the activation handshake.
		if config.LocalTlsEnforced {
			lme.SetPort(16993)
		}

		client.localManagement = lme
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
	}

	// Detect TLS ClientHello - close existing connection so firmware can renegotiate
	if len(msg.Payload) >= 6 && msg.Payload[0] == 0x16 && msg.Payload[5] == 0x01 && e.lmConnected {
		log.Debug("TLS ClientHello detected, closing existing connection for new handshake")
		e.localManagement.Close()
		e.lmConnected = false
	}

	log.Debug("RPS sent activation data, processing...")

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
			e.HandleDataFromLM(dataFromLM)
			log.Debug("Response sent to RPS, waiting for next RPS message")

			if e.isLME {
				e.waitGroup.Wait()

				if bytes.Contains(msg.Payload, []byte(soapActionGenerateKeyPair)) {
					log.Debugf("LME: pausing %s after GenerateKeyPair to let AMT settle before next channel open", lmePostKeygenPause)
					time.Sleep(lmePostKeygenPause)
				}
			}

			// LME holds a persistent HECI handle whose tcpip-forward registrations
			// are established once in Initialize(); closing it between requests
			// invalidates the device for the next RPS message. MakeItSo's deferred
			// Close() handles end-of-flow teardown for LME.
			if !e.tlsTunnelActive && !e.isLME {
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

	if extraPortSwitchDelaySeconds > 0 {
		log.Infof("Port switch: adding %ds extra delay (RPC_PORT_SWITCH_EXTRA_DELAY)", extraPortSwitchDelaySeconds)

		delaySeconds += extraPortSwitchDelaySeconds
	}

	log.Infof("Port switch: waiting %ds for AMT TLS restart", delaySeconds)

	// In LME mode there is no LMS daemon to reconnect to; transport stays on
	// HECI/APF and the only thing that changes is the AMT-side port future
	// CHANNEL_OPENs target. Close-and-redial would dial a 127.0.0.1:16993
	// socket that isn't listening (that's why we're on LME in the first
	// place). Keep the LME handle, honour the delay, flip the port.
	if e.isLME {
		if err := waitWithSignal(time.Duration(delaySeconds) * time.Second); err != nil {
			return err
		}

		if lmec, ok := e.localManagement.(*lm.LMEConnection); ok {
			port, perr := strconv.ParseUint(psPayload.Port, 10, 32)
			if perr != nil {
				return fmt.Errorf("port switch: invalid port %q: %w", psPayload.Port, perr)
			}

			lmec.SetPort(uint32(port))
		}

		e.tlsTunnelActive = true

		log.Info("Port switch: LME retargeted to port ", psPayload.Port)

		ackMsg := e.payload.CreateMessageResponse([]byte("ok"), MethodPortSwitchAck)
		if err := e.server.Send(ackMsg); err != nil {
			return err
		}

		log.Info("Port switch: sent port_switch_ack to RPS")

		return nil
	}

	log.Infof("Port switch: closing LMS connection")

	// Close existing LMS connection
	e.localManagement.Close()
	e.lmConnected = false

	// Wait for AMT to restart its TLS subsystem. Use a cancellable wait so a
	// user interrupt (Ctrl+C / SIGTERM) can abort the activation loop promptly
	// instead of being delayed by the full sleep.
	if err := waitWithSignal(time.Duration(delaySeconds) * time.Second); err != nil {
		return err
	}

	// Create new LMS connection channels
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	// Create new plain TCP LMS connection on the TLS port.
	// rpc-go only passes raw bytes — the actual TLS handshake is handled
	// by RPS's TLSTunnelManager through the WebSocket tunnel.
	newLM := lm.NewLMSConnection(
		utils.LMSAddress,
		psPayload.Port,
		true, // useTls: gate Listen's read-timeout strategy for TLS 1.3 quiet rounds; the dial is plain TCP
		lmDataChannel,
		lmErrorChannel,
		0,     // controlMode not needed for port switch
		false, // skipCertCheck not relevant — no TLS at this layer
	)

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

	return nil
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
