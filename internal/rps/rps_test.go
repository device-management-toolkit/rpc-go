/*********************************************************************
* Copyright (c) Intel Corporation 2021
* SPDX-License-Identifier: Apache-2.0
**********************************************************************/
package rps

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

var upgrader = websocket.Upgrader{}

func echo(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	defer c.Close()

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			break
		}

		err = c.WriteMessage(mt, message)
		if err != nil {
			break
		}
	}
}

var testServer *httptest.Server
var testUrl string
var testFlags *flags.Flags

func init() {
	// Create test server with the echo handler.
	testServer = httptest.NewServer(http.HandlerFunc(echo))
	// Convert http to ws
	testFlags = flags.NewFlags([]string{}, MockPRSuccess)
	testUrl = "ws" + strings.TrimPrefix(testServer.URL, "http")
	testFlags.URL = testUrl
}

func TestExecuteCommand(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandActivate
	f.Profile = "profile01"
	f.Password = "testPw"
	rc := ExecuteCommand(f)
	assert.NotEqual(t, nil, rc)
}

func TestSetCommandMethodActivate(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandActivate
	f.Profile = "profile01"
	expected := utils.CommandActivate + " --profile profile01"

	setCommandMethod(f)
	assert.Equal(t, expected, f.Command)
}

func TestSetCommandMethodDeactivate(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandDeactivate
	f.Password = "password"
	expected := utils.CommandDeactivate + " --password password"

	setCommandMethod(f)
	assert.Equal(t, expected, f.Command)
	f.Force = true
	expected += " -f"

	setCommandMethod(f)
	assert.Equal(t, expected, f.Command)
}

func TestSetCommandMethodMaintenanceSynctime(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandMaintenance
	f.SubCommand = "syncclock"
	f.Password = "password"
	expected := utils.CommandMaintenance + " -password password --synctime"

	setCommandMethod(f)
	assert.Equal(t, expected, f.Command)
	f.Command = utils.CommandMaintenance
	f.Force = true
	expected += " -f"

	setCommandMethod(f)
	assert.Equal(t, expected, f.Command)
}

func TestSetCommandMethodMaintenanceSyncHostname(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandMaintenance
	f.SubCommand = "synchostname"
	f.Password = "password"
	expected := utils.CommandMaintenance + " -password password --synchostname"

	setCommandMethod(f)
	assert.Equal(t, expected, f.Command)
}

func TestSetCommandMethodMaintenanceSyncIP(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandMaintenance
	f.SubCommand = "syncip"
	f.Password = "password"
	expected := utils.CommandMaintenance + " -password password --syncip"

	setCommandMethod(f)
	assert.Equal(t, expected, f.Command)
}

func TestSetCommandMethodMaintenanceChangePassword(t *testing.T) {
	f := &flags.Flags{}
	f.Command = utils.CommandMaintenance
	f.Password = "password"
	f.SubCommand = "changepassword"
	expected := utils.CommandMaintenance + " -password password --changepassword"

	setCommandMethod(f)
	assert.Equal(t, expected, f.Command)

	f.Command = utils.CommandMaintenance
	f.StaticPassword = "a_static_password"
	expected += " " + f.StaticPassword
	setCommandMethod(f)
	assert.Equal(t, expected, f.Command)
}

func TestPrepareInitialMessage(t *testing.T) {
	payload, payload1 := PrepareInitialMessage(testFlags)
	assert.NotEqual(t, payload, payload1)
}

func TestConnect(t *testing.T) {
	server := NewAMTActivationServer(testFlags.URL, testFlags.Proxy)
	err := server.Connect(true)

	defer server.Close()

	assert.NoError(t, err)
}
func TestSend(t *testing.T) {
	server := NewAMTActivationServer(testFlags.URL, testFlags.Proxy)
	err := server.Connect(true)

	defer server.Close()

	assert.NoError(t, err)

	message := Message{
		Status: "test",
	}
	server.Send(message)
}
func TestListen(t *testing.T) {
	server := NewAMTActivationServer(testFlags.URL, testFlags.Proxy)
	err := server.Connect(true)

	defer server.Close()

	assert.NoError(t, err)

	var wgAll sync.WaitGroup

	wgAll.Add(1)

	rpsChan := server.Listen()

	go func() {
		for {
			dataFromRPS := <-rpsChan
			assert.Equal(t, []byte("{\"method\":\"\",\"apiKey\":\"\",\"appVersion\":\"\",\"protocolVersion\":\"\",\"status\":\"test\",\"message\":\"\",\"fqdn\":\"\",\"payload\":\"\",\"tenantId\":\"\"}"), dataFromRPS)
			wgAll.Done()

			return
		}
	}()

	message := Message{
		Status: "test",
	}
	server.Send(message)
	wgAll.Wait()
}
func TestProcessMessageHeartbeat(t *testing.T) {
	activation := `{
        "method": "heartbeat_request"
    }`
	server := NewAMTActivationServer(testFlags.URL, testFlags.Proxy)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.NotNil(t, decodedMessage)
}
func TestProcessMessageSuccess(t *testing.T) {
	activation := `{
        "method": "success",
        "message": "{\"status\":\"ok\", \"network\":\"configured\", \"ciraConnection\":\"configured\"}"
    }`
	server := NewAMTActivationServer(testFlags.URL, testFlags.Proxy)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Nil(t, decodedMessage)
}
func TestProcessMessageUnformattedSuccess(t *testing.T) {
	activation := `{
        "method": "success",
        "message": "configured"
    }`
	server := NewAMTActivationServer(testFlags.URL, testFlags.Proxy)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Nil(t, decodedMessage)
}
func TestProcessMessageError(t *testing.T) {
	activation := `{
        "method": "error",
        "message": "can't do it"
    }`
	server := NewAMTActivationServer(testFlags.URL, testFlags.Proxy)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Nil(t, decodedMessage)
}
func TestProcessMessageForLMS(t *testing.T) {
	activation := `{
        "method": "",
        "message": "ok",
        "payload": "eyJzdGF0dXMiOiJvayIsICJuZXR3b3JrIjoiY29uZmlndXJlZCIsICJjaXJhQ29ubmVjdGlvbiI6ImNvbmZpZ3VyZWQifQ=="
    }`
	server := NewAMTActivationServer(testFlags.URL, testFlags.Proxy)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Equal(t, []byte("{\"status\":\"ok\", \"network\":\"configured\", \"ciraConnection\":\"configured\"}"), decodedMessage)
}
