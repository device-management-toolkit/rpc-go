/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"rpc"
	"rpc/internal/amt"
	"rpc/pkg/utils"
)

type Payload struct {
	AMT amt.Interface
}

// Message is used for tranferring messages between RPS and RPC
type Message struct {
	Method          string `json:"method"`
	APIKey          string `json:"apiKey"`
	AppVersion      string `json:"appVersion"`
	ProtocolVersion string `json:"protocolVersion"`
	Status          string `json:"status"`
	Message         string `json:"message"`
	Fqdn            string `json:"fqdn"`
	Payload         string `json:"payload"`
}

// Status Message is used for displaying and parsing status messages from RPS
type StatusMessage struct {
	Status         string
	Network        string
	CIRAConnection string
}

// MessagePayload struct is used for the initial request to RPS to activate a device
type MessagePayload struct {
	Version           string   `json:"ver"`
	Build             string   `json:"build"`
	SKU               string   `json:"sku"`
	UUID              string   `json:"uuid"`
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	CurrentMode       int      `json:"currentMode"`
	Hostname          string   `json:"hostname"`
	FQDN              string   `json:"fqdn"`
	Client            string   `json:"client"`
	CertificateHashes []string `json:"certHashes"`
}

func NewPayload() Payload {
	return Payload{
		AMT: amt.NewAMTCommand(),
	}
}

// createPayload gathers data from ME to assemble required information for sending to the server
func (p Payload) createPayload(dnsSuffix string, hostname string) (MessagePayload, error) {
	payload := MessagePayload{}
	var err error
	payload.Version, err = p.AMT.GetVersionDataFromME("AMT")
	if err != nil {
		return payload, err
	}
	payload.Build, err = p.AMT.GetVersionDataFromME("Build Number")
	if err != nil {
		return payload, err
	}
	payload.SKU, err = p.AMT.GetVersionDataFromME("Sku")
	if err != nil {
		return payload, err
	}
	payload.UUID, err = p.AMT.GetUUID()
	if err != nil {
		return payload, err
	}
	payload.CurrentMode, err = p.AMT.GetControlMode()
	if err != nil {
		return payload, err
	}
	lsa, err := p.AMT.GetLocalSystemAccount()
	if err != nil {
		return payload, err
	}
	payload.Username = lsa.Username
	payload.Password = lsa.Password

	if dnsSuffix != "" {
		payload.FQDN = dnsSuffix
	} else {
		payload.FQDN, err = p.AMT.GetDNSSuffix()
		if payload.FQDN == "" {
			payload.FQDN, _ = p.AMT.GetOSDNSSuffix()
		}
		if err != nil {
			return payload, err
		}
	}
	if hostname != "" {
		payload.Hostname = hostname
	} else {
		payload.Hostname, err = os.Hostname()
		if err != nil {
			return payload, err
		}
	}
	payload.Client = utils.ClientName
	hashes, err := p.AMT.GetCertificateHashes()
	if err != nil {
		return payload, err
	}
	for _, v := range hashes {
		payload.CertificateHashes = append(payload.CertificateHashes, v.Hash)
	}
	return payload, nil

}

// CreateMessageRequest is used for assembling the message to request activation of a device
func (p Payload) CreateMessageRequest(flags rpc.Flags) (Message, error) {
	message := Message{
		Method:          flags.Command,
		APIKey:          "key",
		AppVersion:      utils.ProjectVersion,
		ProtocolVersion: utils.ProtocolVersion,
		Status:          "ok",
		Message:         "ok",
	}
	payload, err := p.createPayload(flags.DNS, flags.Hostname)
	if err != nil {
		return message, err
	}
	// Update with AMT password for activated devices
	if payload.CurrentMode != 0 {
		if flags.Password == "" {
			for flags.Password == "" {
				fmt.Println("Please enter AMT Password: ")
				// Taking input from user
				_, err = fmt.Scanln(&flags.Password)
				if err != nil {
					return message, err
				}
			}
		}
		payload.Password = flags.Password
	}
	//convert struct to json
	data, err := json.Marshal(payload)
	if err != nil {
		return message, err
	}

	message.Payload = base64.StdEncoding.EncodeToString(data)

	return message, nil
}

// CreateMessageResponse is used for creating a response to the server
func (p Payload) CreateMessageResponse(payload []byte) Message {
	message := Message{
		Method:          "response",
		APIKey:          "key",
		AppVersion:      utils.ProjectVersion,
		ProtocolVersion: utils.ProtocolVersion,
		Status:          "ok",
		Message:         "ok",
		Payload:         base64.StdEncoding.EncodeToString(payload),
	}
	return message
}
