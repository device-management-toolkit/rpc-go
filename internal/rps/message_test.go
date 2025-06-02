/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

var MockPRSuccess = new(MockPasswordReaderSuccess)
var MockPRFail = new(MockPasswordReaderFail)

type MockPasswordReaderSuccess struct{}

func (mpr *MockPasswordReaderSuccess) ReadPassword() (string, error) {
	return utils.TestPassword, nil
}

type MockPasswordReaderFail struct{}

func (mpr *MockPasswordReaderFail) ReadPassword() (string, error) {
	return "", errors.New("Read password failed")
}

// Mock the AMT Hardware
type MockAMT struct{}

var mebxDNSSuffix string
var osDNSSuffix string = "osdns"
var controlMode int = 0
var err error = nil
var mode int = 0

func (c MockAMT) Initialize() error {
	return nil
}
func (c MockAMT) GetVersionDataFromME(key string, amtTimeout time.Duration) (string, error) {
	return "Version", nil
}
func (c MockAMT) GetChangeEnabled() (amt.ChangeEnabledResponse, error) {
	return amt.ChangeEnabledResponse(0x01), nil
}
func (c MockAMT) EnableAMT() error                { return nil }
func (c MockAMT) DisableAMT() error               { return nil }
func (c MockAMT) GetUUID() (string, error)        { return "123-456-789", nil }
func (c MockAMT) GetUUIDV2() (string, error)      { return "", nil }
func (c MockAMT) GetControlMode() (int, error)    { return controlMode, nil }
func (c MockAMT) GetControlModeV2() (int, error)  { return controlMode, nil }
func (c MockAMT) GetOSDNSSuffix() (string, error) { return osDNSSuffix, nil }
func (c MockAMT) GetDNSSuffix() (string, error)   { return mebxDNSSuffix, nil }
func (c MockAMT) GetCertificateHashes() ([]amt.CertHashEntry, error) {
	return []amt.CertHashEntry{}, nil
}
func (c MockAMT) GetRemoteAccessConnectionStatus() (amt.RemoteAccessStatus, error) {
	return amt.RemoteAccessStatus{}, nil
}
func (c MockAMT) GetLANInterfaceSettings(useWireless bool) (amt.InterfaceSettings, error) {
	return amt.InterfaceSettings{}, nil
}
func (c MockAMT) GetLocalSystemAccount() (amt.LocalSystemAccount, error) {
	return amt.LocalSystemAccount{Username: "Username", Password: "Password"}, nil
}
func (c MockAMT) Unprovision() (int, error) {
	return mode, nil
}

func (c MockAMT) StartConfigurationHBased(amt.SecureHBasedParameters) (amt.SecureHBasedResponse, error) {
	return amt.SecureHBasedResponse{}, nil
}

var p Payload

func (c MockAMT) InitiateLMS() {}

func init() {
	p = Payload{}
	p.AMT = MockAMT{}
}
func TestCreatePayload(t *testing.T) {
	mebxDNSSuffix = "mebxdns"
	result, err := p.createPayload("", "", 0)
	assert.Equal(t, "Version", result.Version)
	assert.Equal(t, "Version", result.Build)
	assert.Equal(t, "Version", result.SKU)
	assert.Equal(t, "123-456-789", result.UUID)
	assert.Equal(t, "Username", result.Username)
	assert.Equal(t, "Password", result.Password)
	assert.Equal(t, 0, result.CurrentMode)
	assert.NotEmpty(t, result.Hostname)
	assert.Equal(t, "mebxdns", result.FQDN)
	assert.Equal(t, utils.ClientName, result.Client)
	assert.Len(t, result.CertificateHashes, 0)
	assert.NoError(t, err)
}
func TestCreatePayloadWithOSDNSSuffix(t *testing.T) {
	mebxDNSSuffix = ""
	result, err := p.createPayload("", "", 0)
	assert.NoError(t, err)
	assert.Equal(t, "osdns", result.FQDN)
}
func TestCreatePayloadWithDNSSuffix(t *testing.T) {
	result, err := p.createPayload("vprodemo.com", "", 0)
	assert.NoError(t, err)
	assert.Equal(t, "vprodemo.com", result.FQDN)
}

func TestCreatePayloadWithNODNSSuffix(t *testing.T) {
	mebxDNSSuffix = ""
	osDNSSuffix = ""
	err = errors.New("Nope")
	result, err := p.createPayload("", "", 0)
	assert.NoError(t, err)
	assert.Equal(t, "", result.FQDN)
}

func TestCreateActivationRequestNoDNSSuffixProvided(t *testing.T) {
	flags := flags.Flags{
		Command: "method",
	}
	result, err := p.CreateMessageRequest(flags)
	assert.NoError(t, err)
	assert.Equal(t, "method", result.Method)
	assert.Equal(t, "key", result.APIKey)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, "ok", result.Message)
	assert.NotEmpty(t, result.Payload)
	assert.Equal(t, utils.ProtocolVersion, result.ProtocolVersion)
	assert.Equal(t, utils.ProjectVersion, result.AppVersion)
}
func TestCreateActivationRequestNoPasswordShouldPrompt(t *testing.T) {
	controlMode = 1
	flags := flags.NewFlags(nil, MockPRSuccess)
	flags.Command = "method"
	result, err := p.CreateMessageRequest(*flags)
	assert.NoError(t, err)
	assert.NotEmpty(t, result.Payload)
}
func TestCreateActivationRequestWithPasswordShouldNotPrompt(t *testing.T) {
	controlMode = 1
	flags := flags.Flags{
		Command:  "method",
		Password: "password",
	}
	// Restore stdin right after the test.
	defer func() {
		controlMode = 0
	}()

	result, err := p.CreateMessageRequest(flags)
	msgPayload, decodeErr := base64.StdEncoding.DecodeString(result.Payload)
	payload := MessagePayload{}
	jsonErr := json.Unmarshal(msgPayload, &payload)

	assert.NoError(t, err)
	assert.NoError(t, decodeErr)
	assert.NoError(t, jsonErr)
	assert.NotEmpty(t, result.Payload)
	assert.Equal(t, "password", payload.Password)
}

func TestCreateActivationRequestWithDNSSuffix(t *testing.T) {
	flags := flags.Flags{
		Command: "method",
		DNS:     "vprodemo.com",
	}
	result, err := p.CreateMessageRequest(flags)
	assert.NoError(t, err)
	assert.Equal(t, "method", result.Method)
	assert.Equal(t, "key", result.APIKey)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, "ok", result.Message)
	assert.Equal(t, utils.ProtocolVersion, result.ProtocolVersion)
	assert.Equal(t, utils.ProjectVersion, result.AppVersion)
}

func TestCreateActivationResponse(t *testing.T) {
	result := p.CreateMessageResponse([]byte("123"))
	assert.Equal(t, "response", result.Method)
	assert.Equal(t, "key", result.APIKey)
	assert.Equal(t, "ok", result.Status)
	assert.Equal(t, "ok", result.Message)
	assert.NotEmpty(t, result.Payload)
	assert.Equal(t, utils.ProtocolVersion, result.ProtocolVersion)
	assert.Equal(t, utils.ProjectVersion, result.AppVersion)
}

func TestCreateMessageRequestIPConfiguration(t *testing.T) {
	flags := flags.Flags{
		IpConfiguration: flags.IPConfiguration{
			IpAddress:    "192.168.1.1",
			Netmask:      "255.255.0.0",
			Gateway:      "192.168.1.0",
			PrimaryDns:   "8.8.8.8",
			SecondaryDns: "1.2.3.4",
		},
	}
	result, createErr := p.CreateMessageRequest(flags)
	assert.NoError(t, createErr)
	assert.NotEmpty(t, result.Payload)
	decodedBytes, decodeErr := base64.StdEncoding.DecodeString(result.Payload)
	assert.NoError(t, decodeErr)

	msgPayload := MessagePayload{}
	jsonErr := json.Unmarshal(decodedBytes, &msgPayload)
	assert.NoError(t, jsonErr)
	assert.Equal(t, flags.IpConfiguration, msgPayload.IPConfiguration)
}

func TestCreateMessageRequestCustomUUID(t *testing.T) {
	flags := flags.Flags{
		UUID: "12345678-1234-1234-1234-123456789012",
	}
	result, createErr := p.CreateMessageRequest(flags)
	assert.NoError(t, createErr)
	assert.NotEmpty(t, result.Payload)
	decodedBytes, decodeErr := base64.StdEncoding.DecodeString(result.Payload)
	assert.NoError(t, decodeErr)

	msgPayload := MessagePayload{}
	jsonErr := json.Unmarshal(decodedBytes, &msgPayload)
	assert.NoError(t, jsonErr)
	assert.Equal(t, flags.UUID, msgPayload.UUID)
}

func TestCreateMessageRequestNoUUID(t *testing.T) {
	const expectedUUID = "123-456-789"

	flags := flags.Flags{}
	result, createErr := p.CreateMessageRequest(flags)
	assert.NoError(t, createErr)
	assert.NotEmpty(t, result.Payload)
	decodedBytes, decodeErr := base64.StdEncoding.DecodeString(result.Payload)
	assert.NoError(t, decodeErr)

	msgPayload := MessagePayload{}
	jsonErr := json.Unmarshal(decodedBytes, &msgPayload)
	assert.NoError(t, jsonErr)
	assert.Equal(t, expectedUUID, msgPayload.UUID)
}

func TestCreateMessageRequestHostnameInfo(t *testing.T) {
	flags := flags.Flags{
		HostnameInfo: flags.HostnameInfo{
			DnsSuffixOS: "os.test.com",
			Hostname:    "test-hostname-012",
		},
	}
	result, createErr := p.CreateMessageRequest(flags)
	assert.NoError(t, createErr)
	assert.NotEmpty(t, result.Payload)
	decodedBytes, decodeErr := base64.StdEncoding.DecodeString(result.Payload)
	assert.NoError(t, decodeErr)

	msgPayload := MessagePayload{}
	jsonErr := json.Unmarshal(decodedBytes, &msgPayload)
	assert.NoError(t, jsonErr)
	assert.Equal(t, flags.HostnameInfo, msgPayload.HostnameInfo)
}

func TestCreateMessageRequestFriendlyName(t *testing.T) {
	expectedName := "friendlyName01"
	flags := flags.Flags{
		FriendlyName: expectedName,
	}
	result, createErr := p.CreateMessageRequest(flags)
	assert.NoError(t, createErr)
	assert.NotEmpty(t, result.Payload)
	decodedBytes, decodeErr := base64.StdEncoding.DecodeString(result.Payload)
	assert.NoError(t, decodeErr)

	var m map[string]interface{}
	unmarshalErr := json.Unmarshal(decodedBytes, &m)
	assert.NoError(t, unmarshalErr)
	assert.Equal(t, m["friendlyName"], expectedName)
}
func TestCreateMessageRequestWithoutFriendlyName(t *testing.T) {
	flags := flags.Flags{}
	result, createErr := p.CreateMessageRequest(flags)
	assert.NoError(t, createErr)
	assert.NotEmpty(t, result.Payload)
	decodedBytes, decodeErr := base64.StdEncoding.DecodeString(result.Payload)
	assert.NoError(t, decodeErr)

	var m map[string]interface{}
	unmarshalErr := json.Unmarshal(decodedBytes, &m)
	assert.NoError(t, unmarshalErr)

	_, isInMap := m["friendlyName"]
	assert.False(t, isInMap)
}
