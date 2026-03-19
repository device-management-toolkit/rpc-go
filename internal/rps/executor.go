/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"context"
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

type Executor struct {
	server          AMTActivationServer
	localManagement lm.LocalMananger
	isLME           bool
	lmeConnected    bool
	payload         Payload
	data            chan []byte
	errors          chan error
	waitGroup       *sync.WaitGroup
	lastError       error
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

// MakeItSo uses a pointer receiver because it updates executor state (lmeConnected, lastError)
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

	// AMT closes APF channels after each response, so we must open a new channel
	// for each request. However, the Listen goroutine stays running (reads from /dev/mei0).
	if e.isLME {
		// LME: Open fresh channel for each request (AMT closes after each response)
		log.Debug("LME: Opening new APF channel for this request")

		err := e.localManagement.Connect()
		if err != nil {
			e.lastError = fmt.Errorf("failed to open LME channel: %w", err)
			log.Error(err)

			return true
		}
		// After the first successful Connect/channel-open, start the persistent Listen goroutine.
		// This avoids running Listen concurrently with the initial session/channel initialization.
		if !e.lmeConnected {
			log.Debug("LME: First message - starting persistent Listen goroutine")

			go e.localManagement.Listen()

			e.lmeConnected = true
		}

		// Wait for APF channel-open confirmation before sending request data.
		// This avoids sending APF channel data on a channel AMT has not confirmed yet.
		e.waitGroup.Wait()
		log.Trace("Channel open confirmation received")
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
			log.Debug("Received response from LME, forwarding to RPS")
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
			// Timeout waiting for response from AMT/LME
			// This indicates AMT is not responding - treat as an error
			log.Error("Timeout waiting for LME response - AMT not responding")

			e.lastError = fmt.Errorf("timeout waiting for AMT response after %d seconds", utils.AMTResponseTimeout)

			return true
		}
	}
}

func (e Executor) HandleDataFromLM(data []byte) {
	if len(data) > 0 {
		log.Debug("received data from LMX")
		log.Trace(string(data))

		err := e.server.Send(e.payload.CreateMessageResponse(data))
		if err != nil {
			log.Error(err)
		}
	}
}
