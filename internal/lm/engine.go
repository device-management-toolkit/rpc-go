/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"sync"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/apf"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
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

// apfInitHandler signals ready once ME advertises tcpip-forward for port 16992.
type apfInitHandler struct {
	apf.DefaultHandler
	portForwardReady bool
}

func (h *apfInitHandler) OnGlobalRequest(req apf.GlobalRequest) bool {
	if req.RequestType == "tcpip-forward" && req.Port == 16992 {
		h.portForwardReady = true
	}

	return false
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

// Initialize runs the APF handshake until ME signals tcpip-forward on 16992 (or HECI times out).
func (lme *LMEConnection) Initialize() error {
	lme.Command.Close()

	if err := lme.Command.Open(true); err != nil {
		logLMEError(err)

		return err
	}

	handler := &apfInitHandler{}
	processor := apf.NewProcessor(handler)

	var pv bytes.Buffer
	if err := binary.Write(&pv, binary.BigEndian, apf.ProtocolVersion(1, 0, 9)); err != nil {
		return err
	}

	if err := lme.Command.Send(pv.Bytes()); err != nil {
		logLMEError(err)

		return err
	}

	for {
		result, bytesRead, err := lme.Command.Receive()
		if err != nil {
			if errors.Is(err, heci.ErrReadTimeout) || strings.Contains(err.Error(), "heci read timeout") {
				// ME went idle; handshake phase is complete.
				return nil
			}

			logLMEError(err)

			return err
		}

		if bytesRead == 0 {
			// No more init messages queued.
			return nil
		}

		reply := processor.Process(result[:bytesRead], lme.Session)
		if reply.Len() > 0 {
			if err := lme.Command.Send(reply.Bytes()); err != nil {
				logLMEError(err)

				return err
			}
		}

		if handler.portForwardReady {
			return nil
		}
	}
}

// Connect initializes connection to LME via MEI Driver
func (lme *LMEConnection) Connect() error {
	log.Debug("Sending APF_CHANNEL_OPEN")

	// Reset per-request session state before a new channel open.
	lme.Session.Tempdata = []byte{}
	lme.Session.SenderChannel = 0
	lme.Session.TXWindow = 0
	lme.Session.HandshakeConfirmed = false

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
				// Add delay after Initialize to give device time to stabilize.
				utils.Pause(utils.HeciRetryDelay / 1000)

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

func logLMEError(err error) {
	if err == nil {
		return
	}

	if errors.Is(err, heci.ErrReadTimeout) || strings.Contains(err.Error(), "heci read timeout") {
		log.Warn(err)

		return
	}

	log.Error(err)
}

// Send writes data to LMS TCP Socket
func (lme *LMEConnection) Send(data []byte) error {
	log.Debug("sending message to LME")
	log.Trace(string(data))

	// Use the proper APF serialization function instead of manual binary.Write
	channelDataBytes := apf.BuildChannelDataBytes(lme.Session.SenderChannel, data)

	// Debit TX window by payload length, not framed length.
	if sent := uint32(len(data)); sent >= lme.Session.TXWindow {
		lme.Session.TXWindow = 0
	} else {
		lme.Session.TXWindow -= sent
	}

	err := lme.Command.Send(channelDataBytes)
	if err != nil {
		return err
	}

	log.Debug("sent message to LME")

	return nil
}

// Listen dispatches APF messages for one transaction, then exits on CHANNEL_CLOSE or OPEN_FAILURE.
func (lme *LMEConnection) Listen() {
	for {
		result, bytesRead, err := lme.Command.Receive()
		if bytesRead == 0 || err != nil {
			log.Trace("NO MORE DATA TO READ")

			// Non-blocking send so a closed error channel doesn't leak the goroutine.
			if err != nil {
				select {
				case lme.Session.ErrorBuffer <- err:
				default:
					log.Debug("Error channel closed, exiting Listen")
				}
			}

			return
		}

		msg := result[:bytesRead]
		msgType := msg[0]

		reply := apf.Process(msg, lme.Session)
		if reply.Len() > 0 {
			if err := lme.Command.Send(reply.Bytes()); err != nil {
				log.Trace(err)

				return
			}
		}

		// One transaction per Listen; Process already handed off body/error.
		if msgType == apf.APF_CHANNEL_OPEN_FAILURE {
			return
		}

		// HandshakeConfirmed guards against stale CLOSE frames from a previous channel (reset by Connect)
		if msgType == apf.APF_CHANNEL_CLOSE && lme.Session.HandshakeConfirmed {
			return
		}
	}
}

// Close closes the LME connection
func (lme *LMEConnection) Close() error {
	log.Debug("closing connection to lme")
	lme.Command.Close()

	return nil
}
