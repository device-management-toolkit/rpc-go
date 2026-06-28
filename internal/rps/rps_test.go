/*********************************************************************
* Copyright (c) Intel Corporation 2021
* SPDX-License-Identifier: Apache-2.0
**********************************************************************/
package rps

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
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

var (
	testServer *httptest.Server
	testUrl    string
	testFlags  *flags.Flags
)

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
	server := NewAMTActivationServer(testFlags)
	err := server.Connect(true)

	defer server.Close()

	assert.NoError(t, err)
}

func TestSend(t *testing.T) {
	server := NewAMTActivationServer(testFlags)
	err := server.Connect(true)

	defer server.Close()

	assert.NoError(t, err)

	message := Message{
		Status: "test",
	}
	server.Send(message)
}

func TestListen(t *testing.T) {
	server := NewAMTActivationServer(testFlags)
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
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.NotNil(t, decodedMessage)
}

func TestProcessMessageSuccess(t *testing.T) {
	activation := `{
        "method": "success",
        "message": "{\"status\":\"ok\", \"network\":\"configured\", \"ciraConnection\":\"configured\"}"
    }`
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Nil(t, decodedMessage)
}

func TestProcessMessageProgress(t *testing.T) {
	activation := `{
        "method": "progress",
        "message": "Configuring network settings"
    }`
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	// Hook after Connect so only ProcessMessage's output is captured.
	logHook := test.NewGlobal()
	defer logHook.Reset()

	decodedMessage := server.ProcessMessage([]byte(activation))
	// Sentinel (never nil) keeps the executor loop alive.
	assert.Equal(t, ProgressSentinel, string(decodedMessage))
	// Progress is logged at info level so it shows without -v.
	entry := logHook.LastEntry()
	assert.NotNil(t, entry)
	assert.Equal(t, logrus.InfoLevel, entry.Level)
	assert.Equal(t, "Configuring network settings", entry.Message)
}

func TestProcessMessageProgressJSONOutputLogged(t *testing.T) {
	activation := `{
        "method": "progress",
        "message": "Configuring network settings"
    }`
	jsonFlags := flags.NewFlags([]string{}, MockPRSuccess)
	jsonFlags.JsonOutput = true
	server := NewAMTActivationServer(jsonFlags)
	server.Connect(true)

	// Hook after Connect so only ProcessMessage's output is captured.
	logHook := test.NewGlobal()
	defer logHook.Reset()

	decodedMessage := server.ProcessMessage([]byte(activation))
	// Sentinel still returned in --json mode.
	assert.Equal(t, ProgressSentinel, string(decodedMessage))
	// Progress is logged in --json mode too (no special suppression).
	entry := logHook.LastEntry()
	assert.NotNil(t, entry)
	assert.Equal(t, "Configuring network settings", entry.Message)
}

func TestProcessMessageStructuredSuccess(t *testing.T) {
	// RPS rps#2665 structured per-component result rides alongside the legacy flat fields.
	activation := `{
        "method": "success",
        "message": "{\"Status\":\"Admin control mode.\",\"Components\":{\"Activation\":{\"Result\":\"Success\",\"Mode\":\"Admin control mode.\"},\"WirelessNetwork\":{\"Result\":\"Failure\",\"Details\":\"Failed to add 1\"}}}"
    }`
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Nil(t, decodedMessage)
}

// captureLogOutput runs fn with logrus output redirected to a buffer and returns it.
func captureLogOutput(fn func()) string {
	var buf bytes.Buffer

	orig := logrus.StandardLogger().Out

	logrus.SetOutput(&buf)

	defer logrus.SetOutput(orig)

	fn()

	return buf.String()
}

func TestLogStatusMessageStructured(t *testing.T) {
	// Structured Components present: Success at info level, Failure at error level.
	statusMessage := StatusMessage{
		Status: "Admin control mode.",
		Components: &ComponentResults{
			Activation:      &ComponentResult{Result: ComponentResultSuccess, Mode: "Admin control mode."},
			WirelessNetwork: &ComponentResult{Result: ComponentResultFailure, Details: "Failed to add 1"},
			CIRAProxy:       &ComponentResult{Result: ComponentResultNotApplicable, Details: "CIRA proxy not part of this configuration"},
		},
	}

	out := captureLogOutput(func() { logStatusMessage(statusMessage) })
	assert.Contains(t, out, "level=info")
	assert.Contains(t, out, "Activation:")
	assert.Contains(t, out, "level=error")
	assert.Contains(t, out, "Wireless Network:")
	assert.Contains(t, out, "Failed to add 1")
	// NotApplicable components are dropped from the summary.
	assert.NotContains(t, out, "CIRA Proxy")
	assert.NotContains(t, out, "CIRA proxy not part of this configuration")
}

func TestLogStatusMessageStructuredSurfacesHeaderAndMode(t *testing.T) {
	// The structured branch logs the static header, and each component line must
	// surface Mode inline when present (Activation shows [ACM]).
	statusMessage := StatusMessage{
		Status: "already enabled in admin mode.",
		Components: &ComponentResults{
			Activation:      &ComponentResult{Result: ComponentResultSuccess, Mode: "ACM", Details: "Already enabled in admin mode"},
			WirelessNetwork: &ComponentResult{Result: ComponentResultSuccess, Mode: "LocalProfileSync", Details: "Local Profile Sync Configured"},
		},
	}

	out := captureLogOutput(func() { logStatusMessage(statusMessage) })
	assert.Contains(t, out, "Provisioning and Configuration Result : ")
	assert.Contains(t, out, "Activation:")
	assert.Contains(t, out, "Already enabled in admin mode")
	assert.Contains(t, out, "[ACM]")
	assert.Contains(t, out, "Wireless Network:")
	assert.Contains(t, out, "[LocalProfileSync]")
}

func TestLogStatusMessageLegacyFallback(t *testing.T) {
	// No Components: falls back to legacy flat-field logging.
	statusMessage := StatusMessage{
		Status:           "Admin control mode.",
		Network:          "configured",
		CIRAConnection:   "configured",
		TLSConfiguration: "configured",
	}

	assert.NotPanics(t, func() { logStatusMessage(statusMessage) })
}

func TestProcessMessageUnformattedSuccess(t *testing.T) {
	activation := `{
        "method": "success",
        "message": "configured"
    }`
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Nil(t, decodedMessage)
}

func TestProcessMessageError(t *testing.T) {
	activation := `{
        "method": "error",
        "message": "can't do it"
    }`
	server := NewAMTActivationServer(testFlags)
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
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Equal(t, []byte("{\"status\":\"ok\", \"network\":\"configured\", \"ciraConnection\":\"configured\"}"), decodedMessage)
}

func TestProcessMessageTLSData(t *testing.T) {
	rawPayload := []byte("client_hello")
	encodedPayload := base64.StdEncoding.EncodeToString(rawPayload)
	activation := `{
        "method": "tls_data",
        "payload": "` + encodedPayload + `"
    }`

	server := NewAMTActivationServer(testFlags)
	server.Connect(true)
	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Equal(t, rawPayload, decodedMessage)
}

func TestProcessMessagePortSwitch(t *testing.T) {
	portSwitchJSON := `{"port":"16993","delay":50}`
	activation, err := json.Marshal(Message{
		Method:  MethodPortSwitch,
		Payload: portSwitchJSON,
	})
	assert.NoError(t, err)

	server := NewAMTActivationServer(testFlags)
	server.Connect(true)
	decodedMessage := server.ProcessMessage(activation)
	assert.Equal(t, []byte(PortSwitchSentinel+portSwitchJSON), decodedMessage)
}
