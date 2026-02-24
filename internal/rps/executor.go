/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
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
		case dataFromServer := <-rpsDataChannel:
			shallIReturn := e.HandleDataFromRPS(dataFromServer)
			if shallIReturn { // quits the loop -- we're either done or reached a point where we need to stop
				close(e.data)
				close(e.errors)

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
	close(e.data)
	close(e.errors)

	err := e.server.Close()
	if err != nil {
		log.Error("Connection close failed", err)

		return
	}
}

func (e *Executor) HandleDataFromRPS(dataFromServer []byte) bool {
	msgPayload := e.server.ProcessMessage(dataFromServer)
	if msgPayload == nil {
		log.Info("RPS sent terminal message (success/error), ending activation flow")

		return true
	} else if string(msgPayload) == "heartbeat" {
		log.Debug("Received heartbeat from RPS, continuing")

		return false
	}

	log.Debug("RPS sent activation data, processing...")

	// AMT closes APF channels after each response, so we must open a new channel
	// for each request. However, the Listen goroutine stays running (reads from /dev/mei0).
	if e.isLME && !e.lmeConnected {
		// First LME message: start persistent Listen goroutine
		log.Debug("LME: First message - starting persistent Listen goroutine")

		go e.localManagement.Listen()

		e.lmeConnected = true
	}

	if e.isLME {
		// LME: Open fresh channel for each request (AMT closes after each response)
		log.Debug("LME: Opening new APF channel for this request")

		err := e.localManagement.Connect()
		if err != nil {
			log.Error(err)

			return true
		}

		// Wait for AMT to confirm channel is open
		e.waitGroup.Wait()
		log.Trace("Channel open confirmation received")
	} else {
		// LMS: open/close connection for every request
		err := e.localManagement.Connect()
		if err != nil {
			log.Error(err)

			return true
		}

		go e.localManagement.Listen()
		defer e.localManagement.Close()
	}

	// send our data to LMX
	err := e.localManagement.Send(msgPayload)
	if err != nil {
		log.Error(err)

		return true
	}

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
				// Filter out "heci read timeout" - it's a normal timeout from the HECI driver
				// when waiting for data. Real data comes through the e.data channel.
				if errFromLMS.Error() == "heci read timeout" {
					log.Debug("heci read timeout (normal driver timeout, not an error)")

					continue
				}

				log.Error("error from LMS: ", errFromLMS)
				// Only terminate on real errors, not normal connection closure
				e.lastError = fmt.Errorf("LME/LMS error: %w", errFromLMS)

				return true
			}
		case <-time.After(utils.AMTResponseTimeout * time.Second):
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
