/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type Executor struct {
	server           AMTActivationServer
	localManagement  lm.LocalMananger
	isLME            bool
	payload          Payload
	data             chan []byte
	errors           chan error
	waitGroup        *sync.WaitGroup
	localTlsEnforced bool
	lmConnected      bool // tracks if LMS connection is active (for TLS tunnel persistence)
}

func NewExecutor(flags flags.Flags) (Executor, error) {
	// these are closed in the close function for each lm implementation
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	port := utils.LMSPort
	if flags.LocalTlsEnforced {
		port = utils.LMSTLSPort
	}

	client := Executor{
		server:           NewAMTActivationServer(&flags),
		localManagement:  lm.NewLMSConnection(utils.LMSAddress, port, flags.LocalTlsEnforced, lmDataChannel, lmErrorChannel, flags.ControlMode, flags.SkipAmtCertCheck),
		data:             lmDataChannel,
		errors:           lmErrorChannel,
		waitGroup:        &sync.WaitGroup{},
		localTlsEnforced: flags.LocalTlsEnforced,
	}

	// TEST CONNECTION TO SEE IF LMS EXISTS
	log.Debugf("Attempting LMS connection on port %s (TLS: %t)", port, flags.LocalTlsEnforced)

	err := client.localManagement.Connect()
	if err != nil {
		if flags.LocalTlsEnforced {
			return client, utils.LMSConnectionFailed
		}
		// client.localManagement.Close()
		log.Debug("LMS not running, using LME Connection")

		client.localManagement = lm.NewLMEConnection(lmDataChannel, lmErrorChannel, client.waitGroup)
		client.isLME = true
		client.localManagement.Initialize()
	} else {
		log.Debug("Using existing LMS connection")
		client.localManagement.Close()
	}

	err = client.server.Connect(flags.SkipCertCheck)
	if err != nil {
		// TODO: should the connection be closed?
		// client.localManagement.Close()
		log.Error("error connecting to RPS")
	}

	return client, err
}

func (e *Executor) MakeItSo(messageRequest Message) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	rpsDataChannel := e.server.Listen()

	log.Debug("sending activation request to RPS")

	err := e.server.Send(messageRequest)
	if err != nil {
		log.Error(err.Error())

		return
	}

	defer e.localManagement.Close()

	for {
		select {
		case dataFromServer := <-rpsDataChannel:
			shallIReturn := e.HandleDataFromRPS(dataFromServer)
			if shallIReturn { // quits the loop -- we're either done or reached a point where we need to stop
				close(e.data)
				close(e.errors)

				return
			}
		case <-interrupt:
			e.HandleInterrupt()

			return
		}
	}
}

func (e *Executor) HandleInterrupt() {
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
		return true
	} else if string(msgPayload) == "heartbeat" {
		return false
	}

	// Detect TLS ClientHello - need to close old connection for new handshake
	isTLSClientHello := len(msgPayload) >= 6 && msgPayload[0] == 0x16 && msgPayload[5] == 0x01
	if isTLSClientHello && e.lmConnected {
		e.localManagement.Close()
		e.lmConnected = false
	}

	if !e.localTlsEnforced || !e.lmConnected {
		err := e.localManagement.Connect()
		if err != nil {
			log.Error(err)
			return true
		}
		e.lmConnected = true

		if e.isLME {
			go e.localManagement.Listen()
			e.waitGroup.Wait()
		}
	}

	if !e.isLME {
		go e.localManagement.Listen()
	}

	err := e.localManagement.Send(msgPayload)
	if err != nil {
		log.Error(err)
		return true
	}

	for {
		select {
		case dataFromLM := <-e.data:
			if len(dataFromLM) == 0 {
				if e.localTlsEnforced {
					log.Warn("Empty response from LMS - sending connection_reset")
					e.localManagement.Close()
					e.lmConnected = false
					resetMsg := e.payload.CreateMessageResponse([]byte("connection_closed"), MethodConnectionReset)
					e.server.Send(resetMsg)
				}
				return false
			}

			e.HandleDataFromLM(dataFromLM)

			if e.isLME {
				e.waitGroup.Wait()
			}

			if !e.localTlsEnforced {
				e.localManagement.Close()
				e.lmConnected = false
			}

			return false
		case errFromLMS := <-e.errors:
			if errFromLMS != nil {
				log.Error("LMS error: ", errFromLMS)
				return true
			}
		}
	}
}

func (e *Executor) HandleDataFromLM(data []byte) {
	if len(data) > 0 {
		method := "response"
		if e.localTlsEnforced {
			method = MethodTLSData
		}
		err := e.server.Send(e.payload.CreateMessageResponse(data, method))
		if err != nil {
			log.Error(err)
		}
	}
}
