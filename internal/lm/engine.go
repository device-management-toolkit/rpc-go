/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"bytes"
	"encoding/binary"
	"sync"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/apf"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// LMConnection is struct for managing connection to LMS
type LMEConnection struct {
	Command    pthi.Command
	Session    *apf.Session
	ourChannel int
	retries    int
}

func NewLMEConnection(data chan []byte, errors chan error, wg *sync.WaitGroup) *LMEConnection {
	lme := &LMEConnection{
		ourChannel: 1,
	}
	lme.Command = pthi.NewCommand()
	lme.Session = &apf.Session{
		DataBuffer:  data,
		ErrorBuffer: errors,
		Tempdata:    []byte{},
		WaitGroup:   wg,
	}

	return lme
}

func (lme *LMEConnection) Initialize() error {
	// Ensure any previous device handle is closed before opening a new one
	lme.Command.Close()

	err := lme.Command.Open(true)
	if err != nil {
		log.Error(err)

		return err
	}

	var bin_buf bytes.Buffer

	protocolVersion := apf.ProtocolVersion(1, 0, 9)
	binary.Write(&bin_buf, binary.BigEndian, protocolVersion)

	err = lme.execute(bin_buf)
	if err != nil {
		log.Error(err)

		return err
	}

	return nil
}

// Connect initializes connection to LME via MEI Driver
func (lme *LMEConnection) Connect() error {
	log.Debug("Sending APF_CHANNEL_OPEN")

	// Issue #7 fix: Reset session state before new connection
	if lme.Session.Timer != nil {
		lme.Session.Timer.Stop()
		// Reset the existing timer instead of creating a new one
		// (timer goroutine is waiting on this timer's channel)
		lme.Session.Timer.Reset(utils.LMETimerTimeout * time.Second)
	} else {
		// First time only - create the timer
		lme.Session.Timer = time.NewTimer(utils.LMETimerTimeout * time.Second)
	}

	lme.Session.Tempdata = []byte{}
	lme.Session.SenderChannel = 0
	lme.Session.TXWindow = 0

	var lastErr error

	for attempts := 0; attempts < 4; attempts++ {
		channel := ((lme.ourChannel + 1) % 32)
		if channel == 0 {
			lme.ourChannel = 1
		} else {
			lme.ourChannel = channel
		}

		bin_buf := apf.ChannelOpen(lme.ourChannel)

		err := lme.Command.Send(bin_buf.Bytes())
		if err != nil {
			lastErr = err
			if attempts < 4 && (err.Error() == "no such device" || err.Error() == "The device is not connected.") {
				log.Warn(err.Error())
				log.Warn("Retrying...")

				if initErr := lme.Initialize(); initErr != nil {
					return initErr
				}
				// Issue #1 fix: Add delay after Initialize to give device time to stabilize
				time.Sleep(utils.HeciRetryDelay * time.Millisecond)

				continue
			}

			log.Error(err)

			return err
		}

		lme.retries = 0
		lme.Session.WaitGroup.Add(1)

		return nil
	}

	return lastErr
}

// Send writes data to LMS TCP Socket
func (lme *LMEConnection) Send(data []byte) error {
	log.Debug("sending message to LME")
	log.Trace(string(data))

	var bin_buf bytes.Buffer

	channelData := apf.ChannelData(lme.Session.SenderChannel, data)
	binary.Write(&bin_buf, binary.BigEndian, channelData.MessageType)
	binary.Write(&bin_buf, binary.BigEndian, channelData.RecipientChannel)
	binary.Write(&bin_buf, binary.BigEndian, channelData.DataLength)
	binary.Write(&bin_buf, binary.BigEndian, channelData.Data)

	lme.Session.TXWindow -= lme.Session.TXWindow // hmmm

	err := lme.Command.Send(bin_buf.Bytes())
	if err != nil {
		return err
	}

	log.Debug("sent message to LME")

	return nil
}

func (lme *LMEConnection) execute(bin_buf bytes.Buffer) error {
	for {
		result, err := lme.Command.Call(bin_buf.Bytes(), bin_buf.Len())
		if err != nil && (err.Error() == "empty response from AMT" || err.Error() == "no such device") {
			log.Warn("AMT Unavailable, retrying...")

			break
		} else if err != nil {
			return err
		}

		bin_buf = apf.Process(result, lme.Session)
		if bin_buf.Len() == 0 {
			log.Debug("done EXECUTING.........")

			break
		}
	}

	return nil
}

// Listen reads data from the LMS socket connection
func (lme *LMEConnection) Listen() {
	timerDone := make(chan struct{})
	defer close(timerDone)

	// Ensure timer exists before selecting on Timer.C
	if lme.Session.Timer == nil {
		lme.Session.Timer = time.NewTimer(utils.LMETimerTimeout * time.Second)
	}

	// Timer goroutine - handles timer expirations for ALL channels
	go func() {
		for {
			select {
			case <-lme.Session.Timer.C:
				// Timer fired - send accumulated data
				select {
				case lme.Session.DataBuffer <- lme.Session.Tempdata:
				case <-timerDone:
					return
				}

				lme.Session.Tempdata = []byte{}

				var bin_buf bytes.Buffer

				channelData := apf.ChannelClose(lme.Session.SenderChannel)
				binary.Write(&bin_buf, binary.BigEndian, channelData.MessageType)
				binary.Write(&bin_buf, binary.BigEndian, channelData.RecipientChannel)

				lme.Command.Send(bin_buf.Bytes())
			case <-timerDone:
				if lme.Session.Timer != nil {
					lme.Session.Timer.Stop()
				}

				return
			}
		}
	}()

	for {
		result2, bytesRead, err2 := lme.Command.Receive()
		if bytesRead == 0 || err2 != nil {
			log.Trace("NO MORE DATA TO READ")
			// Issue #3 fix: Send error to channel before exiting to prevent deadlock
			// But don't panic if channel is closed
			if err2 != nil {
				select {
				case lme.Session.ErrorBuffer <- err2:
				default:
					log.Debug("Error channel closed, exiting Listen")
				}
			}

			break
		} else {
			result := apf.Process(result2, lme.Session)
			if result.Len() != 0 {
				err2 = lme.execute(result)
				if err2 != nil {
					log.Trace(err2)
				}

				log.Trace(result)
			}
		}
	}
}

// Close closes the LME connection

func (lme *LMEConnection) Close() error {
	log.Debug("closing connection to lme")
	lme.Command.Close()

	if lme.Session.Timer != nil {
		lme.Session.Timer.Stop()
	}

	return nil
}
