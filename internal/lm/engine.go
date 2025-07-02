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

	channel := ((lme.ourChannel + 1) % 32)
	if channel == 0 {
		lme.ourChannel = 1
	} else {
		lme.ourChannel = channel
	}

	lme.Session.WaitGroup.Add(1)
	bin_buf := apf.ChannelOpen(lme.ourChannel)

	err := lme.Command.Send(bin_buf.Bytes(), uint32(bin_buf.Len()))
	if err != nil {
		lme.retries = lme.retries + 1
		if lme.retries < 3 && (err.Error() == "no such device" || err.Error() == "The device is not connected.") {
			log.Warn(err.Error())
			log.Warn("Retrying...")
			// retry connection/initialization to device if it doesn't respond
			err = lme.Initialize()
			if err == nil {
				return lme.Connect()
			}
		} else {
			log.Error(err)
		}

		return err
	}

	lme.retries = 0

	return nil
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

	err := lme.Command.Send(bin_buf.Bytes(), uint32(bin_buf.Len()))
	if err != nil {
		return err
	}

	log.Debug("sent message to LME")

	return nil
}

func (lme *LMEConnection) execute(bin_buf bytes.Buffer) error {
	for {
		result, err := lme.Command.Call(bin_buf.Bytes(), uint32(bin_buf.Len()))
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
	go func() {
		lme.Session.Timer = time.NewTimer(2 * time.Second)
		<-lme.Session.Timer.C

		lme.Session.DataBuffer <- lme.Session.Tempdata

		lme.Session.Tempdata = []byte{}

		var bin_buf bytes.Buffer

		channelData := apf.ChannelClose(lme.Session.SenderChannel)
		binary.Write(&bin_buf, binary.BigEndian, channelData.MessageType)
		binary.Write(&bin_buf, binary.BigEndian, channelData.RecipientChannel)

		lme.Command.Send(bin_buf.Bytes(), uint32(bin_buf.Len()))
	}()

	for {
		result2, bytesRead, err2 := lme.Command.Receive()
		if bytesRead == 0 || err2 != nil {
			log.Trace("NO MORE DATA TO READ")

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
