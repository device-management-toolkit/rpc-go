/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// AMTActivationServer struct represents the connection to RPS
type AMTActivationServer struct {
	URL   string
	Conn  *websocket.Conn
	flags *flags.Flags
}

func ExecuteCommand(flags *flags.Flags) error {
	setCommandMethod(flags)

	startMessage, err := PrepareInitialMessage(flags)
	if err != nil {
		return err
	}

	executor, err := NewExecutor(*flags)
	if err != nil {
		return err
	}

	executor.MakeItSo(startMessage)

	return nil
}

func setCommandMethod(flags *flags.Flags) {
	switch flags.Command {
	case utils.CommandActivate:
		flags.Command += " --profile " + flags.Profile
	case utils.CommandDeactivate:
		flags.Command += " --password " + flags.Password
	case utils.CommandMaintenance:
		flags.Command += " -password " + flags.Password

		task := flags.SubCommand
		if task == "syncclock" {
			task = "synctime"
		}

		flags.Command += " --" + task
		if task == "changepassword" && flags.StaticPassword != "" {
			flags.Command += " " + flags.StaticPassword
		}
	}

	if flags.Force {
		flags.Command += " -f"
	}
}

// TODO: suggest this be renamed to RemoteProvisioningService
func NewAMTActivationServer(flags *flags.Flags) AMTActivationServer {
	amtactivationserver := AMTActivationServer{
		URL:   flags.URL,
		flags: flags,
	}

	return amtactivationserver
}
func PrepareInitialMessage(flags *flags.Flags) (Message, error) {
	payload := NewPayload()
	return payload.CreateMessageRequest(*flags)
}

// Connect is used to connect to the RPS Server
func (amt *AMTActivationServer) Connect(skipCertCheck bool) error {
	log.Info("connecting to ", amt.URL)
	log.Info(amt.URL)

	var err error

	websocketDialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipCertCheck,
		},
	}

	if amt.flags.Proxy != "" {
		// Parse the URL of the proxy.
		proxyURL, err := url.Parse(amt.flags.Proxy)
		if err != nil {
			panic(err)
		}

		websocketDialer.Proxy = func(*http.Request) (*url.URL, error) {
			return proxyURL, nil
		}
	} else {
		websocketDialer.Proxy = http.ProxyFromEnvironment
	}

	var resp *http.Response

	amt.Conn, resp, err = websocketDialer.Dial(amt.URL, nil)
	if err != nil {
		defer resp.Body.Close()
		return err
	}

	log.Info("connected to ", amt.URL)

	return nil
}

// Close closes the connection to rps
func (amt *AMTActivationServer) Close() error {
	log.Info("closed RPS connection")

	err := amt.Conn.Close()
	if err != nil {
		return err
	}

	return nil
}

// Send is used for sending data to the RPS Server
func (amt *AMTActivationServer) Send(data Message) error {
	dataToSend, err := json.Marshal(data)
	if err != nil {
		log.Error("unable to marshal activationResponse to JSON")
		return err
	}

	log.Debug("sending message to RPS")

	err = amt.Conn.WriteMessage(websocket.TextMessage, dataToSend)
	if err != nil {
		return err
	}

	return nil
}

// Listen is used for listening to responses from RPS
func (amt *AMTActivationServer) Listen() chan []byte {
	log.Debug("listening to RPS...")

	dataChannel := make(chan []byte)

	go func() {
		defer close(dataChannel)

		for {
			_, message, err := amt.Conn.ReadMessage()
			if err != nil {
				log.Error("error:", err)
				break
			}
			dataChannel <- message
		}
	}()

	return dataChannel
}

// ProcessMessage inspects RPS messages, decodes the base64 payload from the server and relays it to LMS
func (amt *AMTActivationServer) ProcessMessage(message []byte) []byte {
	log.Debug("received messages from RPS")

	activation := Message{}

	err := json.Unmarshal(message, &activation)
	if err != nil {
		log.Println(err)
		return nil
	}

	if activation.Method == "heartbeat_request" {
		heartbeat, _ := amt.GenerateHeartbeatResponse(activation)
		return heartbeat
	}

	statusMessage := StatusMessage{}

	switch activation.Method {
	case "success":
		err := json.Unmarshal([]byte(activation.Message), &statusMessage)
		if err != nil {
			log.Error(err)
			log.Info(activation.Message)
		} else {
			log.Info("Status: " + statusMessage.Status)
			log.Info("Network: " + statusMessage.Network)
			log.Info("CIRA: " + statusMessage.CIRAConnection)
			log.Info("TLS: " + statusMessage.TLSConfiguration)
		}

		return nil
	case "error":
		err := json.Unmarshal([]byte(activation.Message), &statusMessage)
		if err == nil {
			log.Error(statusMessage.Status)
		} else {
			log.Error(activation.Message)
		}

		return nil
	}

	msgPayload, err := base64.StdEncoding.DecodeString(activation.Payload)
	if err != nil {
		log.Error("unable to decode base64 payload from RPS")
	}

	log.Trace("PAYLOAD:" + string(msgPayload))

	return msgPayload
}
func (amt *AMTActivationServer) GenerateHeartbeatResponse(activation Message) ([]byte, error) {
	activation.Method = "heartbeat_response"
	activation.Status = "success"

	err := amt.Send(activation)
	if err != nil {
		log.Error("Heartbeat send failure")
		return nil, err
	}

	return []byte("heartbeat"), nil
}
