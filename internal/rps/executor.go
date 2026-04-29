/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"bytes"
	"context"
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
	isCommitChanges bool // Track if current message is CommitChanges to apply targeted diagnostics
}
type ExecutorConfig struct {
	URL              string
	Proxy            string
	LocalTlsEnforced bool
	SkipAmtCertCheck bool
	ControlMode      int
	SkipCertCheck    bool
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
	msgPayload, terminal, err := e.server.ProcessMessage(dataFromServer)
	if err != nil {
		e.lastError = err

		return true
	}

	if terminal {
		log.Info("RPS sent terminal message (success/error), ending activation flow")

		return true
	} else if string(msgPayload) == "heartbeat" {
		log.Debug("Received heartbeat from RPS, continuing")

		return false
	}

	log.Debug("RPS sent activation data, processing...")

	isAdminSetup := isAdminSetupRequest(msgPayload)

	// For CommitChanges, track this and ensure we start with a fresh connection to reset digest auth context
	// CommitChanges may fail with 401 if device doesn't support "admin" credentials for this operation
	// but device is already provisioned by AdminSetup, so we'll handle 401 gracefully
	e.isCommitChanges = isCommitChangesRequest(msgPayload)
	if e.isCommitChanges {
		log.Debug("CommitChanges detected - closing any existing connections to force fresh auth")
		e.localManagement.Close()
	}

	// AMT closes the APF channel after each response, so we open a new channel and
	// start a fresh Listen goroutine per request. Listen exits on CHANNEL_CLOSE.
	if e.isLME {
		log.Debug("LME: Opening new APF channel for this request")

		// Fresh handshake WaitGroup per request: if a prior Listen exited without
		// signaling Done(), the old WG is abandoned rather than deadlocking this one.
		handshake := e.resetHandshake()

		// Drain the WG on the way out so anything still waiting on it never leaks,
		// even when Listen exits before the APF handshake completes.
		defer func() {
			defer func() { _ = recover() }()

			handshake.Done()
		}()

		err := e.localManagement.Connect()
		if err != nil {
			e.lastError = fmt.Errorf("failed to open LME channel: %w", err)
			log.Error(err)

			return true
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
				e.lastError = fmt.Errorf("LME error during channel open: %w", errFromLMS)
				log.Error(e.lastError)

				return true
			}
		case <-time.After(handshakeTimeout):
			e.lastError = fmt.Errorf("timed out waiting for APF channel open after %s", handshakeTimeout)
			log.Error(e.lastError)

			return true
		}
	} else {
		// LMS: open/close connection for every request
		err := e.localManagement.Connect()
		if err != nil {
			e.lastError = fmt.Errorf("failed to connect to LMS: %w", err)
			log.Error(err)

			return true
		}

		go e.localManagement.Listen()
		defer e.localManagement.Close()
	}

	// send our data to LMX
	err = e.localManagement.Send(msgPayload)
	if err != nil {
		e.lastError = fmt.Errorf("failed to send payload to LME/LMS: %w", err)
		log.Error(err)

		return true
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), utils.AMTResponseTimeout*time.Second)
	defer cancel()

	for {
		select {
		case dataFromLM := <-e.data:
			if len(dataFromLM) == 0 {
				// AMT closes the LMS connection without sending a response for AdminSetup.
				// This is expected behavior — synthesize a success response so RPS can
				// proceed to verify the provisioning state via IPS_HostBasedSetupService GET.
				if isAdminSetup {
					log.Warn("AdminSetup: AMT closed connection without responding (expected); sending synthetic success response")

					fallbackResponse := buildAdminSetupFallbackResponse(msgPayload)
					e.HandleDataFromLM(fallbackResponse)

					return false
				}

				e.lastError = errors.New("empty response from LMS/LME")
				log.Error(e.lastError)

				return true
			}

			log.Debug("Received response from LME, forwarding to RPS")

			if isAdminSetup {
				if rv, ok := extractSetupReturnValue(dataFromLM); ok && rv != 0 {
					if rv == 1 {
						fallbackSucceeded, fallbackErr := e.tryAdminSetupFallback(msgPayload)
						if fallbackErr != nil {
							e.lastError = fmt.Errorf("AMT Setup returned NotSupported and AdminSetup fallback failed: %w", fallbackErr)
							log.Error(e.lastError)
							e.HandleDataFromLM(dataFromLM)

							return true
						}

						if fallbackSucceeded {
							log.Warn("AMT Setup returned NotSupported; AdminSetup fallback succeeded, synthesizing Setup success for RPS")
							e.HandleDataFromLM(buildSetupFallbackResponse(msgPayload))

							return false
						}
					}

					e.lastError = formatSetupReturnValueError(rv)
					log.Error(e.lastError)
					e.HandleDataFromLM(dataFromLM)

					return true
				}
			}

			if e.isCommitChanges && bytes.Contains(dataFromLM, []byte("401 Unauthorized")) {
				e.lastError = errors.New("AMT CommitChanges returned 401 Unauthorized; likely prior Setup did not complete successfully")
				log.Error(e.lastError)
				e.HandleDataFromLM(dataFromLM)

				return true
			}

			e.HandleDataFromLM(dataFromLM)
			log.Debug("Response sent to RPS, waiting for next RPS message")
			// Note: For subsequent LME messages, we reuse the connection
			// No need to wait for anything - just return after sending response to RPS

			return false
		case errFromLMS := <-e.errors:
			if errFromLMS != nil {
				// HECI read timeout is expected while polling for data.
				if errors.Is(errFromLMS, heci.ErrReadTimeout) {
					log.Debug("heci read timeout (normal driver timeout, not an error)")

					continue
				}

				log.Error("error from LMS: ", errFromLMS)
				// Only terminate on real errors, not normal connection closure
				e.lastError = fmt.Errorf("LME/LMS error: %w", errFromLMS)

				return true
			}
		case <-timeoutCtx.Done():
			log.Error("Timeout waiting for LME response - AMT not responding")

			e.lastError = fmt.Errorf("timeout waiting for AMT response after %d seconds", utils.AMTResponseTimeout)

			return true
		}
	}
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

func isAdminSetupRequest(payload []byte) bool {
	// RPS sends "Setup" action for device provisioning (which is AMT's AdminSetup operation)
	return bytes.Contains(payload, []byte("IPS_HostBasedSetupService/Setup")) ||
		bytes.Contains(payload, []byte("<h:Setup_INPUT")) ||
		bytes.Contains(payload, []byte("IPS_HostBasedSetupService/AdminSetup")) ||
		bytes.Contains(payload, []byte("<h:AdminSetup_INPUT"))
}

func isCommitChangesRequest(payload []byte) bool {
	// CommitChanges often fails with stale digest auth nonce, so we close the connection
	// before this command to force fresh authentication negotiation
	return bytes.Contains(payload, []byte("AMT_SetupAndConfigurationService/CommitChanges")) ||
		bytes.Contains(payload, []byte("<h:CommitChanges_INPUT"))
}

func buildAdminSetupFallbackResponse(requestPayload []byte) []byte {
	return buildSetupServiceSuccessResponse(requestPayload, "AdminSetup", "AdminSetup_OUTPUT")
}

func buildSetupFallbackResponse(requestPayload []byte) []byte {
	return buildSetupServiceSuccessResponse(requestPayload, "Setup", "Setup_OUTPUT")
}

func buildSetupServiceSuccessResponse(requestPayload []byte, actionName string, outputTag string) []byte {
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

func rewriteSetupToAdminSetupPayload(payload []byte) ([]byte, bool) {
	request := string(payload)

	if !strings.Contains(request, "IPS_HostBasedSetupService/Setup") || !strings.Contains(request, "<h:Setup_INPUT") {
		return nil, false
	}

	rewritten := strings.ReplaceAll(request, "IPS_HostBasedSetupService/Setup", "IPS_HostBasedSetupService/AdminSetup")
	rewritten = strings.ReplaceAll(rewritten, "<h:Setup_INPUT", "<h:AdminSetup_INPUT")
	rewritten = strings.ReplaceAll(rewritten, "</h:Setup_INPUT>", "</h:AdminSetup_INPUT>")

	return []byte(rewritten), true
}

func (e *Executor) tryAdminSetupFallback(originalSetupPayload []byte) (bool, error) {
	if e.isLME {
		return false, nil
	}

	adminSetupPayload, ok := rewriteSetupToAdminSetupPayload(originalSetupPayload)
	if !ok {
		return false, nil
	}

	log.Warn("Attempting AdminSetup fallback after Setup returned NotSupported")

	e.localManagement.Close()

	if err := e.localManagement.Connect(); err != nil {
		return false, fmt.Errorf("failed to connect to LMS for AdminSetup fallback: %w", err)
	}
	defer e.localManagement.Close()

	go e.localManagement.Listen()

	if err := e.localManagement.Send(adminSetupPayload); err != nil {
		return false, fmt.Errorf("failed to send AdminSetup fallback payload: %w", err)
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), utils.AMTResponseTimeout*time.Second)
	defer cancel()

	for {
		select {
		case dataFromLM := <-e.data:
			if len(dataFromLM) == 0 {
				// AdminSetup may complete by silently closing the socket.
				return true, nil
			}

			if rv, ok := extractSetupReturnValue(dataFromLM); ok && rv == 0 {
				return true, nil
			}

			return false, nil
		case errFromLMS := <-e.errors:
			if errFromLMS != nil && !errors.Is(errFromLMS, heci.ErrReadTimeout) {
				return false, fmt.Errorf("LMS error during AdminSetup fallback: %w", errFromLMS)
			}
		case <-timeoutCtx.Done():
			return false, fmt.Errorf("timeout waiting for AdminSetup fallback response")
		}
	}
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
		log.Debug("received data from LMX")
		log.Trace(string(data))

		err := e.server.Send(e.payload.CreateMessageResponse(data))
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

func extractTagValue(payload []byte, openTag string, closeTag string) (string, bool) {
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
