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

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/lm"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type Executor struct {
	server          AMTActivationServer
	localManagement lm.LocalMananger
	isLME           bool
	payload         Payload
	data            chan []byte
	errors          chan error
	waitGroup       *sync.WaitGroup
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
		server:          NewAMTActivationServer(&flags),
		localManagement: lm.NewLMSConnection(utils.LMSAddress, port, flags.LocalTlsEnforced, lmDataChannel, lmErrorChannel, flags.ControlMode),
		data:            lmDataChannel,
		errors:          lmErrorChannel,
		waitGroup:       &sync.WaitGroup{},
	}

	// TEST CONNECTION TO SEE IF LMS EXISTS
	err := client.localManagement.Connect()

	if err != nil {
		if flags.LocalTlsEnforced {
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

	err = client.server.Connect(flags.SkipCertCheck)
	if err != nil {
		log.Error("error connecting to RPS")
		// TODO: should the connection be closed?
		// client.localManagement.Close()
	}

	return client, err
}

func (e Executor) MakeItSo(messageRequest Message) {
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
			if shallIReturn { //quits the loop -- we're either done or reached a point where we need to stop
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

func (e Executor) HandleDataFromRPS(dataFromServer []byte) bool {
	msgPayload := e.server.ProcessMessage(dataFromServer)
	if msgPayload == nil {
		return true
	} else if string(msgPayload) == "heartbeat" {
		return false
	}

	// send channel open
	err := e.localManagement.Connect()
	go e.localManagement.Listen()

	if err != nil {
		log.Error(err)
		return true
	}

	if e.isLME {
		// wait for channel open confirmation
		e.waitGroup.Wait()
		log.Trace("Channel open confirmation received")
	} else {
		//with LMS we open/close websocket on every request, so setup close for when we're done handling LMS data
		defer e.localManagement.Close()
	}

	// send our data to LMX
	err = e.localManagement.Send(msgPayload)
	if err != nil {
		log.Error(err)
		return true
	}

	for {
		select {
		case dataFromLM := <-e.data:
			e.HandleDataFromLM(dataFromLM)

			if e.isLME {
				e.waitGroup.Wait()
			}

			return false
		case errFromLMS := <-e.errors:
			if errFromLMS != nil {
				log.Error("error from LMS")
				return true
			}
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
