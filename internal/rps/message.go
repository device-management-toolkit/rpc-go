/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
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
	TenantID        string `json:"tenantId"`
}

// Status Message is used for displaying and parsing status messages from RPS
type StatusMessage struct {
	Status           string `json:"Status,omitempty"`
	Network          string `json:"Network,omitempty"`
	CIRAConnection   string `json:"CIRAConnection,omitempty"`
	TLSConfiguration string `json:"TLSConfiguration,omitempty"`
}

// MessagePayload struct is used for the initial request to RPS to activate or manage a device
type MessagePayload struct {
	Version           string          `json:"ver"`
	Build             string          `json:"build"`
	SKU               string          `json:"sku"`
	Features          string          `json:"features"`
	UUID              string          `json:"uuid"`
	Username          string          `json:"username"`
	Password          string          `json:"password"`
	CurrentMode       int             `json:"currentMode"`
	Hostname          string          `json:"hostname"`
	FQDN              string          `json:"fqdn"`
	Client            string          `json:"client"`
	CertificateHashes []string        `json:"certHashes"`
	IPConfiguration   IPConfiguration `json:"ipConfiguration"`
	HostnameInfo      HostnameInfo    `json:"hostnameInfo"`
	FriendlyName      string          `json:"friendlyName,omitempty"`
	TLSEnforced       bool            `json:"tlsEnforced,omitempty"`
	TLSTunnel         bool            `json:"tlsTunnel,omitempty"`
}

// MethodTLSData is the method type for TLS tunnel data passthrough
const MethodTLSData = "tls_data"

// MethodConnectionReset notifies RPS that the LMS connection was closed and needs to be re-established
const MethodConnectionReset = "connection_reset"

// MethodPortSwitch is sent by RPS to tell rpc-go to switch LMS to a TLS port
const MethodPortSwitch = "port_switch"

// MethodPortSwitchAck is sent by rpc-go to confirm it has reconnected on the TLS port
const MethodPortSwitchAck = "port_switch_ack"

// PortSwitchPayload is the JSON payload from RPS's port_switch message
type PortSwitchPayload struct {
	Port     string `json:"port"`
	RootCert string `json:"rootCert"`
	Delay    int    `json:"delay"`
}

func NewPayload() Payload {
	return Payload{
		AMT: amt.NewAMTCommand(),
	}
}

// knownInvalidUUIDs contains UUIDs that should be rejected during activation.
// These UUIDs indicate AMT firmware is in an invalid/corrupted state.
var knownInvalidUUIDs = []string{
	"00000000-0000-0000-0000-000000000000", // Nil UUID - indicates uninitialized/error state
	"03000200-0400-0500-0006-000700080009", // AMT firmware in corrupted/invalid state
}

// isKnownInvalidUUID checks if the UUID is in the list of known invalid UUIDs
func isKnownInvalidUUID(uuid string) bool {
	for _, invalidUUID := range knownInvalidUUIDs {
		if uuid == invalidUUID {
			return true
		}
	}

	return false
}

// createPayload gathers data from ME to assemble required information for sending to the server
func (p Payload) createPayload(dnsSuffix, hostname string, amtTimeout time.Duration) (MessagePayload, error) {
	payload := MessagePayload{}

	var err error

	wired, err := p.AMT.GetLANInterfaceSettings(false)
	if err != nil {
		return payload, err
	}

	if wired.LinkStatus != "up" {
		log.Warn("link status is down, unable to activate AMT in Admin Control Mode (ACM)")
	}

	payload.Version, err = p.AMT.GetVersionDataFromME("AMT", amtTimeout)
	if err != nil {
		return payload, err
	}

	payload.Build, err = p.AMT.GetVersionDataFromME("Build Number", amtTimeout)
	if err != nil {
		return payload, err
	}

	payload.SKU, err = p.AMT.GetVersionDataFromME("Sku", amtTimeout)
	if err != nil {
		return payload, err
	}

	payload.Features = utils.DecodeAMTFeatures(payload.Version, payload.SKU)

	payload.UUID, err = p.AMT.GetUUID()
	if err != nil {
		return payload, err
	}

	// Validate UUID is not a known invalid value
	if isKnownInvalidUUID(payload.UUID) {
		return payload, utils.InvalidUUID
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

	if dnsSuffix != "" {
		payload.FQDN = dnsSuffix
	} else {
		payload.FQDN, _ = p.AMT.GetDNSSuffix()
		// Trim whitespace and a trailing . because MEBx may not allow
		// unsetting the DNS suffix entry by setting it to an empty string
		payload.FQDN = strings.TrimSuffix(strings.TrimSpace(payload.FQDN), ".")
		if payload.FQDN == "" {
			payload.FQDN, _ = p.AMT.GetOSDNSSuffix()
		}

		if payload.FQDN == "" {
			log.Warn("DNS suffix is empty, unable to activate AMT in admin Control Mode (ACM)")
		}
	}

	return payload, nil
}

// CreateMessageRequest is used for assembling the message to request activation of a device
func (p Payload) CreateMessageRequest(req Request) (Message, error) {
	message := Message{
		Method:          req.Command,
		APIKey:          "key",
		AppVersion:      utils.ProjectVersion,
		ProtocolVersion: utils.ProtocolVersion,
		Status:          "ok",
		Message:         "ok",
		TenantID:        req.TenantID,
	}

	payload, err := p.createPayload(req.DNS, req.Hostname, req.AMTTimeoutDuration)
	if err != nil {
		return message, err
	}

	payload.IPConfiguration = req.IpConfiguration
	payload.HostnameInfo = req.HostnameInfo

	if req.UUID != "" {
		if isKnownInvalidUUID(req.UUID) {
			return message, utils.InvalidUUID
		}

		payload.UUID = req.UUID
	}

	// Update with AMT password for activated devices
	if payload.CurrentMode != 0 {
		// When device is already configured, RPC expects an AMT password to be provided
		if req.Password == "" {
			return message, utils.MissingOrIncorrectPassword
		}

		payload.Password = req.Password
	}

	payload.FriendlyName = req.FriendlyName
	payload.TLSEnforced = req.LocalTlsEnforced
	payload.TLSTunnel = req.TLSTunnel

	// convert struct to json
	data, err := json.Marshal(payload)
	if err != nil {
		return message, err
	}

	message.Payload = base64.StdEncoding.EncodeToString(data)

	return message, nil
}

// CreateMessageResponse is used for creating a response to the server
func (p Payload) CreateMessageResponse(payload []byte, method string) Message {
	return Message{
		Method:          method,
		APIKey:          "key",
		AppVersion:      utils.ProjectVersion,
		ProtocolVersion: utils.ProtocolVersion,
		Status:          "ok",
		Message:         "ok",
		Payload:         base64.StdEncoding.EncodeToString(payload),
	}
}
