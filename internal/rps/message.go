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

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type Payload struct {
	AMT amt.Interface
	// Host inventory sources reported to RPS on activation. A nil source
	// leaves its fields out of the payload.
	UPID         upid.Interface
	OSInfo       func() utils.OSInfo
	SerialNumber func() (string, error)
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
	// Components carries the additive, structured per-component provisioning result
	// introduced by RPS (rps#2665). Older RPS releases omit it; in that case the flat
	// fields above remain the source of truth.
	Components *ComponentResults `json:"Components,omitempty"`
	// Error carries the structured description of the failure that ended the flow
	// (RPS structured provisioning failures). Present only on failure; older RPS
	// releases omit it, in which case Status remains the only failure text.
	Error *ProvisioningError `json:"Error,omitempty"`
}

// ProvisioningError is RPS's structured description of the failure that ended a flow:
// a stable code from the RPS error catalog, the component and state-machine step that
// failed, a human-readable reason, and the raw AMT / HTTP detail when available.
type ProvisioningError struct {
	Code           string `json:"Code"`                     // e.g. AMT_PT_UNSUPPORTED, WSMAN_TIMEOUT, RPS_DB_PROFILE_NOT_FOUND
	Component      string `json:"Component"`                // Activation, WiredNetwork, WirelessNetwork, TLS, CIRAProxy, CIRAConnection, Features, Unconfiguration, Deactivation, Maintenance, TimeSync
	Step           string `json:"Step"`                     // state machine step that failed, e.g. ADD_WIFI_SETTINGS
	Reason         string `json:"Reason"`                   // human-readable description of Code
	AmtReturnValue *int   `json:"AmtReturnValue,omitempty"` // raw AMT / CIM method ReturnValue when the failure came from a method response
	HttpStatus     *int   `json:"HttpStatus,omitempty"`     // HTTP status when the failure came from an HTTP-level WSMAN response
	WsmanCall      string `json:"WsmanCall,omitempty"`      // WSMAN call AMT was answering, as Class.Method, when the device is what failed
	Detail         string `json:"Detail,omitempty"`         // underlying error text when it adds information beyond Reason
}

// Component result status values, mirroring the RPS ComponentResultStatus enum (rps#2665).
const (
	ComponentResultSuccess       = "Success"
	ComponentResultFailure       = "Failure"
	ComponentResultNotApplicable = "NotApplicable"
)

// ComponentResult is the per-component outcome of an activation step.
type ComponentResult struct {
	Result  string `json:"Result"`            // Success, Failure, or NotApplicable
	Mode    string `json:"Mode,omitempty"`    // optional mode, e.g. ACM or LocalProfileSync
	Details string `json:"Details,omitempty"` // optional human-readable note (failure reason on failure)
	// Structured failure detail added by RPS alongside Details; present only on Failure.
	Code           string `json:"Code,omitempty"`           // failure code from the RPS error catalog
	Step           string `json:"Step,omitempty"`           // state machine step that failed
	AmtReturnValue *int   `json:"AmtReturnValue,omitempty"` // raw AMT / CIM method ReturnValue when applicable
	Reason         string `json:"Reason,omitempty"`         // human-readable description of Code
	HttpStatus     *int   `json:"HttpStatus,omitempty"`     // HTTP status when the failure came from an HTTP-level WSMAN response
	WsmanCall      string `json:"WsmanCall,omitempty"`      // WSMAN call AMT was answering, as Class.Method, when the device is what failed
	Detail         string `json:"Detail,omitempty"`         // underlying error text when it adds information beyond Reason
}

// ComponentResults groups the structured per-component activation results.
type ComponentResults struct {
	Activation      *ComponentResult `json:"Activation,omitempty"`
	WiredNetwork    *ComponentResult `json:"WiredNetwork,omitempty"`
	WirelessNetwork *ComponentResult `json:"WirelessNetwork,omitempty"`
	TLS             *ComponentResult `json:"TLS,omitempty"`
	CIRAProxy       *ComponentResult `json:"CIRAProxy,omitempty"`
	CIRAConnection  *ComponentResult `json:"CIRAConnection,omitempty"`
	// Network, Features and Unconfiguration are sent only when that step failed. Network is the
	// shared network setup that runs before the wired and wireless configuration.
	Network         *ComponentResult `json:"Network,omitempty"`
	Features        *ComponentResult `json:"Features,omitempty"`
	Unconfiguration *ComponentResult `json:"Unconfiguration,omitempty"`
}

// all returns every component entry, in display order.
func (c *ComponentResults) all() []*ComponentResult {
	return []*ComponentResult{
		c.Activation, c.Network, c.WiredNetwork, c.WirelessNetwork, c.TLS, c.CIRAProxy, c.CIRAConnection, c.Features,
		c.Unconfiguration,
	}
}

// MessagePayload struct is used for the initial request to RPS to activate or manage a device
type MessagePayload struct {
	Version           string                `json:"ver"`
	Build             string                `json:"build"`
	SKU               string                `json:"sku"`
	Features          string                `json:"features"`
	UUID              string                `json:"uuid"`
	Username          string                `json:"username"`
	Password          string                `json:"password"`
	CurrentMode       int                   `json:"currentMode"`
	Hostname          string                `json:"hostname"`
	FQDN              string                `json:"fqdn"`
	Client            string                `json:"client"`
	CertificateHashes []string              `json:"certHashes"`
	IPConfiguration   flags.IPConfiguration `json:"ipConfiguration"`
	HostnameInfo      flags.HostnameInfo    `json:"hostnameInfo"`
	FriendlyName      string                `json:"friendlyName,omitempty"`
	TLSEnforced       bool                  `json:"tlsEnforced,omitempty"`
	TLSTunnel         bool                  `json:"tlsTunnel,omitempty"`
	// ProgressSupported tells RPS this client can handle `progress` messages.
	ProgressSupported bool `json:"progressSupported,omitempty"`
	// WeakAlgorithmsRemoved selects RPS's certificate crypto policy. Nil means
	// the capability probe failed; successful probes report true or false.
	WeakAlgorithmsRemoved *bool `json:"weakAlgorithmsRemoved,omitempty"`

	// Host inventory reported on activation. All fields are best-effort and
	// omitted when unavailable; older RPS releases ignore them.
	OSName       string     `json:"osName,omitempty"`
	OSVersion    string     `json:"osVersion,omitempty"`
	OSDistro     string     `json:"osDistro,omitempty"`
	SerialNumber string     `json:"serialNumber,omitempty"`
	UPID         *upid.Info `json:"upid,omitempty"`
}

// MethodTLSData is the method type for TLS tunnel data passthrough
const MethodTLSData = "tls_data"

// MethodConnectionReset notifies RPS that the LMS connection was closed and needs to be re-established
const MethodConnectionReset = "connection_reset"

// MethodPortSwitch is sent by RPS to tell rpc-go to switch LMS to a TLS port
const MethodPortSwitch = "port_switch"

// MethodPortSwitchAck is sent by rpc-go to confirm it has reconnected on the TLS port
const MethodPortSwitchAck = "port_switch_ack"

// PortSwitchSentinel is the prefix used to detect port_switch payloads in HandleDataFromRPS
const PortSwitchSentinel = "port_switch:"

// MethodProgress is RPS reporting activation progress; informational only.
const MethodProgress = "progress"

// ProgressSentinel marks a progress message so the executor keeps the loop alive.
const ProgressSentinel = "progress:"

// PortSwitchPayload is the JSON payload from RPS's port_switch message
type PortSwitchPayload struct {
	Port     string `json:"port"`
	RootCert string `json:"rootCert"`
	Delay    int    `json:"delay"`
}

func NewPayload() Payload {
	return Payload{
		AMT:          amt.NewAMTCommand(),
		UPID:         upid.NewCommand(),
		OSInfo:       utils.GetOSInfo,
		SerialNumber: utils.GetSystemSerialNumber,
	}
}

// reportsHostInventory reports whether the request should carry host inventory:
// activation, and maintenance syncdeviceinfo (RPS rewrites deviceInfo wholesale
// on sync, so it must resend these fields). flags.Command has already been
// expanded by setCommandMethod (e.g. "activate --profile p"), so only the
// leading word is compared.
func reportsHostInventory(f flags.Flags) bool {
	fields := strings.Fields(f.Command)
	if len(fields) == 0 {
		return false
	}

	switch fields[0] {
	case utils.CommandActivate:
		return true
	case utils.CommandMaintenance:
		return f.SubCommand == utils.SubCommandSyncDeviceInfo
	default:
		return false
	}
}

// addHostInventory populates the OS, serial number, and UPID fields. Failures
// are logged and never block the request: UPID only exists on Tiger Lake and
// newer, and many OEMs leave the SMBIOS serial number blank.
func (p Payload) addHostInventory(payload *MessagePayload) {
	if p.OSInfo != nil {
		osInfo := p.OSInfo()
		payload.OSName = osInfo.Name
		payload.OSVersion = osInfo.Version
		payload.OSDistro = osInfo.Distro
	}

	if p.SerialNumber != nil {
		serial, err := p.SerialNumber()
		if err != nil {
			log.Debugf("Unable to read system serial number: %v", err)
		} else {
			payload.SerialNumber = serial
		}
	}

	if p.UPID == nil {
		return
	}

	platformID, err := p.UPID.GetUPID()
	if err != nil {
		log.Debugf("Unable to read Intel UPID: %v", err)

		return
	}

	payload.UPID = platformID.Info()
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

	// Capability probe, not a provisioning prerequisite: a failure must not abort activation.
	if changeEnabled, cerr := p.AMT.GetChangeEnabled(); cerr != nil {
		log.Warnf("AMT crypto capability: query failed (%v), assuming weak algorithms present", cerr)
	} else {
		weakAlgorithmsRemoved := changeEnabled.AreWeakAlgorithmsRemoved()
		payload.WeakAlgorithmsRemoved = &weakAlgorithmsRemoved

		state := "present"
		if weakAlgorithmsRemoved {
			state = "removed"
		}

		// A clear bit on firmware that predates the field is an assumption, not a report.
		source := "reported"
		if !weakAlgorithmsRemoved && !changeEnabled.IsNewInterfaceVersion() {
			source = "assumed"
		}

		log.Infof("AMT crypto capability (0x%02X): weak algorithms %s, %s",
			uint8(changeEnabled), state, source)
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

	log.Debugf("Retrieved %d certificate hashes from AMT", len(hashes))

	for _, v := range hashes {
		payload.CertificateHashes = append(payload.CertificateHashes, v.Hash)
		log.Debugf("  Certificate: %s (Active: %t, Default: %t)", v.Name, v.IsActive, v.IsDefault)
		log.Tracef("    Hash: %s", v.Hash)
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
func (p Payload) CreateMessageRequest(flags flags.Flags) (Message, error) {
	message := Message{
		Method:          flags.Command,
		APIKey:          "key",
		AppVersion:      utils.ProjectVersion,
		ProtocolVersion: utils.ProtocolVersion,
		Status:          "ok",
		Message:         "ok",
		TenantID:        flags.TenantID,
	}

	payload, err := p.createPayload(flags.DNS, flags.Hostname, flags.AMTTimeoutDuration)
	if err != nil {
		return message, err
	}

	payload.IPConfiguration = flags.IpConfiguration
	payload.HostnameInfo = flags.HostnameInfo
	payload.ProgressSupported = true

	if flags.UUID != "" {
		if isKnownInvalidUUID(flags.UUID) {
			return message, utils.InvalidUUID
		}

		payload.UUID = flags.UUID
	}

	// Update with AMT password for activated devices
	if payload.CurrentMode != 0 {
		if flags.Password == "" {
			for flags.Password == "" {
				if err := flags.ReadPasswordFromUser(); err != nil {
					return message, utils.MissingOrIncorrectPassword
				}
			}
		}

		payload.Password = flags.Password
	}

	payload.FriendlyName = flags.FriendlyName
	payload.TLSEnforced = flags.LocalTlsEnforced
	payload.TLSTunnel = flags.TLSTunnel

	if reportsHostInventory(flags) {
		p.addHostInventory(&payload)
	}

	log.Debug("Creating initial message request")
	log.Debugf("  AMT Version: %s, Build: %s, SKU: %s", payload.Version, payload.Build, payload.SKU)
	log.Debugf("  UUID: %s, Hostname: %s, FQDN: %s", payload.UUID, payload.Hostname, payload.FQDN)
	log.Debugf("  Current Mode: %d, TLS Enforced: %t", payload.CurrentMode, payload.TLSEnforced)
	log.Debugf("  Certificate Hashes: %d", len(payload.CertificateHashes))
	log.Debugf("  OS: %s %s (%s), Serial Number: %s, UPID reported: %t",
		payload.OSName, payload.OSVersion, payload.OSDistro, payload.SerialNumber, payload.UPID != nil)

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
