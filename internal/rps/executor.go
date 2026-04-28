/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
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

	log.Infof("Port switch: closing LMS connection, waiting %ds for AMT TLS restart", psPayload.Delay)

	// Close existing LMS connection
	e.localManagement.Close()
	e.lmConnected = false

	// Wait for AMT to restart its TLS subsystem
	time.Sleep(time.Duration(psPayload.Delay) * time.Second)

	// Create new LMS connection channels
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	// Create new plain TCP LMS connection on the TLS port.
	// rpc-go only passes raw bytes — the actual TLS handshake is handled
	// by RPS's TLSTunnelManager through the WebSocket tunnel.
	newLM := lm.NewLMSConnection(
		utils.LMSAddress,
		psPayload.Port,
		true, // useTls flag (for read timeouts)
		lmDataChannel,
		lmErrorChannel,
		0,     // controlMode not needed for port switch
		false, // skipCertCheck not relevant — no TLS at this layer
	)

	newLM.SetTunnelMode(true)

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
