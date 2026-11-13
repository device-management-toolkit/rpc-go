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
	log "github.com/sirupsen/logrus"
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
	assert.Equal(t, log.InfoLevel, entry.Level)
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

	orig := log.StandardLogger().Out

	log.SetOutput(&buf)

	defer log.SetOutput(orig)

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

func intPtr(v int) *int { return &v }

// errorMessage builds an RPS `error` ClientMsg whose message field is the given Status JSON.
func errorMessage(t *testing.T, status StatusMessage) []byte {
	t.Helper()

	statusJSON, err := json.Marshal(status)
	assert.NoError(t, err)

	activation, err := json.Marshal(Message{Method: "error", Status: "failed", Message: string(statusJSON)})
	assert.NoError(t, err)

	return activation
}

func TestProcessMessageErrorStructured(t *testing.T) {
	// RPS structured failure: Components summary plus the Error block are rendered, and the
	// failing component selects the exit code with the catalog code in Details.
	status := StatusMessage{
		Status:  "Failed to add corp-wifi",
		Network: "Failed to add corp-wifi",
		Error: &ProvisioningError{
			Code:           "AMT_PT_UNSUPPORTED",
			Component:      "WirelessNetwork",
			Step:           "ADD_WIFI_SETTINGS",
			Reason:         "Operation or value is not supported by this AMT firmware",
			AmtReturnValue: intPtr(2066),
		},
		Components: &ComponentResults{
			Activation: &ComponentResult{Result: ComponentResultSuccess, Mode: "ACM", Details: "Device activated in admin control mode"},
			WirelessNetwork: &ComponentResult{
				Result:         ComponentResultFailure,
				Details:        "Failed to add corp-wifi",
				Code:           "AMT_PT_UNSUPPORTED",
				Step:           "ADD_WIFI_SETTINGS",
				AmtReturnValue: intPtr(2066),
			},
			TLS: &ComponentResult{Result: ComponentResultNotApplicable, Details: "TLS not part of this configuration"},
		},
	}
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	var decodedMessage []byte

	out := captureLogOutput(func() { decodedMessage = server.ProcessMessage(errorMessage(t, status)) })

	assert.Nil(t, decodedMessage)

	// Components summary rendered, with the structured suffix on the failed row only.
	assert.Contains(t, out, "Activation:")
	assert.Contains(t, out, "[ACM]")
	assert.NotContains(t, out, "Activation: Device activated in admin control mode [ACM] [")
	assert.Contains(t, out, "Wireless Network:")
	assert.Contains(t, out, "[AMT_PT_UNSUPPORTED @ ADD_WIFI_SETTINGS, ReturnValue 2066]")
	assert.NotContains(t, out, "TLS not part of this configuration")

	// One readable line naming where and why the flow failed.
	assert.Contains(t, out, "level=error")
	assert.Contains(t, out,
		"Provisioning failed [WirelessNetwork/ADD_WIFI_SETTINGS] AMT_PT_UNSUPPORTED: Operation or value is not supported by this AMT firmware (AMT ReturnValue 2066)")

	// Exit code mapped from the failing component, catalog code carried in Details.
	customErr, ok := server.LastError.(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.WiFiConfigurationFailed.Code, customErr.Code)
	assert.Equal(t, utils.WiFiConfigurationFailed.Message, customErr.Message)
	assert.Equal(t, "AMT_PT_UNSUPPORTED", customErr.Details)
}

func TestProcessMessageErrorStructuredWithoutComponents(t *testing.T) {
	// Error block without Components (e.g. a pre-activation database failure).
	status := StatusMessage{
		Status: "Failed to get amt profile from database",
		Error: &ProvisioningError{
			Code:       "RPS_DB_PROFILE_NOT_FOUND",
			Component:  "Activation",
			Step:       "GET_AMT_PROFILE",
			Reason:     "AMT profile could not be read from the database",
			HttpStatus: intPtr(500),
			Detail:     "connection refused",
		},
	}
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	out := captureLogOutput(func() { server.ProcessMessage(errorMessage(t, status)) })
	assert.NotContains(t, out, "Provisioning and Configuration Result")
	assert.Contains(t, out,
		"Provisioning failed [Activation/GET_AMT_PROFILE] RPS_DB_PROFILE_NOT_FOUND: AMT profile could not be read from the database (HTTP 500; connection refused)")

	customErr, ok := server.LastError.(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.ActivationFailed.Code, customErr.Code)
}

func TestProcessMessageErrorLegacy(t *testing.T) {
	// Older RPS without the Error block: single-line Status at error level, no exit code change.
	activation := `{
        "method": "error",
        "message": "{\"Status\":\"Failed to add mps\",\"Network\":\"Wired configured\"}"
    }`
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	logHook := test.NewGlobal()
	defer logHook.Reset()

	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Nil(t, decodedMessage)
	assert.Nil(t, server.LastError)

	entry := logHook.LastEntry()
	assert.NotNil(t, entry)
	assert.Equal(t, log.ErrorLevel, entry.Level)
	assert.Equal(t, "Failed to add mps", entry.Message)
}

func TestProcessMessageErrorUnmarshalFailure(t *testing.T) {
	// Message is not Status JSON: logged verbatim, no exit code change.
	activation := `{
        "method": "error",
        "message": "request failed"
    }`
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	logHook := test.NewGlobal()
	defer logHook.Reset()

	decodedMessage := server.ProcessMessage([]byte(activation))
	assert.Nil(t, decodedMessage)
	assert.Nil(t, server.LastError)

	entry := logHook.LastEntry()
	assert.NotNil(t, entry)
	assert.Equal(t, log.ErrorLevel, entry.Level)
	assert.Equal(t, "request failed", entry.Message)
}

func TestLogStatusMessageSuccessWithFailedComponentSuffix(t *testing.T) {
	// A success message with a partially failed component renders the structured suffix on the
	// failed row and leaves the success rows untouched.
	statusMessage := StatusMessage{
		Status: "Admin control mode.",
		Components: &ComponentResults{
			Activation: &ComponentResult{Result: ComponentResultSuccess, Mode: "ACM"},
			CIRAProxy: &ComponentResult{
				Result:  ComponentResultFailure,
				Details: "Failed to add proxy-1",
				Code:    "AMT_PT_DUPLICATE",
				Step:    "ADD_PROXY_ACCESS_POINT",
			},
		},
	}

	out := captureLogOutput(func() { logStatusMessage(statusMessage) })
	assert.Contains(t, out, "Activation: [ACM]")
	assert.Contains(t, out, "CIRA Proxy: Failed to add proxy-1 [AMT_PT_DUPLICATE @ ADD_PROXY_ACCESS_POINT]")
}

func TestFailureSuffix(t *testing.T) {
	assert.Equal(t, "", failureSuffix(&ComponentResult{Result: ComponentResultFailure, Details: "legacy"}))
	assert.Equal(t, " [X]", failureSuffix(&ComponentResult{Code: "X"}))
	assert.Equal(t, " [@ STEP]", failureSuffix(&ComponentResult{Step: "STEP"}))
	assert.Equal(t, " [X @ STEP, ReturnValue 1]", failureSuffix(&ComponentResult{Code: "X", Step: "STEP", AmtReturnValue: intPtr(1)}))
}

func TestFormatProvisioningError(t *testing.T) {
	assert.Equal(t,
		"Provisioning failed [TLS] WSMAN_TIMEOUT: Timed out",
		formatProvisioningError(&ProvisioningError{Code: "WSMAN_TIMEOUT", Component: "TLS", Reason: "Timed out"}))
	assert.Equal(t,
		"Provisioning failed [TLS/ADD_CERT] WSMAN_TIMEOUT: Timed out (AMT ReturnValue 2; HTTP 504; Gateway Timeout)",
		formatProvisioningError(&ProvisioningError{
			Code:           "WSMAN_TIMEOUT",
			Component:      "TLS",
			Step:           "ADD_CERT",
			Reason:         "Timed out",
			AmtReturnValue: intPtr(2),
			HttpStatus:     intPtr(504),
			Detail:         "Gateway Timeout",
		}))
}

func TestExitCodeForFailure(t *testing.T) {
	server := NewAMTActivationServer(testFlags)

	cases := map[string]utils.CustomError{
		"Activation":      utils.ActivationFailed,
		"WiredNetwork":    utils.NetworkConfigurationFailed,
		"WirelessNetwork": utils.WiFiConfigurationFailed,
		"TLS":             utils.TLSConfigurationFailed,
		"CIRAProxy":       utils.CIRAConfigurationFailed,
		"CIRAConnection":  utils.CIRAConfigurationFailed,
		"Features":        utils.AMTFeaturesConfigurationFailed,
		"Unconfiguration": utils.DeleteConfigsFailed,
		"Deactivation":    utils.DeactivationFailed,
		"TimeSync":        utils.ActivationFailed, // activation run: the clock step of activation failed
		"Maintenance":     utils.GenericFailure,
		"SomethingNew":    utils.GenericFailure,
	}

	for component, expected := range cases {
		got := server.exitCodeForFailure(&ProvisioningError{Code: "C", Component: component, Reason: "R"})
		assert.Equal(t, expected.Code, got.Code, component)
		assert.Equal(t, expected.Message, got.Message, component)
		assert.Equal(t, "C", got.Details, component)
	}
}

func TestExitCodeForMaintenanceFailureUsesSubCommand(t *testing.T) {
	cases := map[string]utils.CustomError{
		utils.SubCommandSyncClock:      utils.SyncClockFailed,
		utils.SubCommandSyncTime:       utils.SyncClockFailed,
		utils.SubCommandSyncHostname:   utils.SyncHostnameFailed,
		utils.SubCommandSyncIP:         utils.SyncIpFailed,
		utils.SubCommandChangePassword: utils.ChangePasswordFailed,
		utils.SubCommandSyncDeviceInfo: utils.SyncDeviceInfoFailed,
	}

	for subCommand, expected := range cases {
		maintenanceFlags := flags.NewFlags([]string{}, MockPRSuccess)
		maintenanceFlags.SubCommand = subCommand
		server := NewAMTActivationServer(maintenanceFlags)

		got := server.exitCodeForFailure(&ProvisioningError{Code: "AMT_PT_INVALID_TIME", Component: "Maintenance", Reason: "Time value is invalid"})
		assert.Equal(t, expected.Code, got.Code, subCommand)
		assert.Equal(t, "AMT_PT_INVALID_TIME", got.Details, subCommand)

		// RPS reports the time machine under TimeSync; in a maintenance run it maps the same way.
		gotTimeSync := server.exitCodeForFailure(&ProvisioningError{Code: "WSMAN_TIMEOUT", Component: "TimeSync", Reason: "Timed out"})
		assert.Equal(t, expected.Code, gotTimeSync.Code, subCommand)
	}
}

func TestFormatProvisioningErrorNamesWsmanCall(t *testing.T) {
	assert.Equal(t,
		"Provisioning failed [WirelessNetwork/ADD_WIFI_SETTINGS] AMT_PT_UNSUPPORTED: Not supported (AMT_WiFiPortConfigurationService.AddWiFiSettings; AMT ReturnValue 2066)",
		formatProvisioningError(&ProvisioningError{
			Code:           "AMT_PT_UNSUPPORTED",
			Component:      "WirelessNetwork",
			Step:           "ADD_WIFI_SETTINGS",
			Reason:         "Not supported",
			WsmanCall:      "AMT_WiFiPortConfigurationService.AddWiFiSettings",
			AmtReturnValue: intPtr(2066),
		}))
}

func TestProcessMessageErrorSanitizesServerText(t *testing.T) {
	// Control characters from the server must not reach the terminal or forge extra log lines.
	status := StatusMessage{
		Status: "Failed",
		Error: &ProvisioningError{
			Code:      "WSMAN_TIMEOUT",
			Component: "TLS",
			Step:      "ADD_CERT\x1b[2J",
			Reason:    "Timed out\nlevel=info msg=\"Activation succeeded\"",
			Detail:    "bell\x07",
		},
	}
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	out := captureLogOutput(func() { server.ProcessMessage(errorMessage(t, status)) })
	assert.Contains(t, out,
		"Provisioning failed [TLS/ADD_CERT [2J] WSMAN_TIMEOUT: Timed out level=info msg=\\\"Activation succeeded\\\" (bell )")

	customErr, ok := server.LastError.(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.TLSConfigurationFailed.Code, customErr.Code)
	assert.Equal(t, "WSMAN_TIMEOUT", customErr.Details)
	assert.Equal(t, "", sanitizeText(""))
	assert.Equal(t, "a b", sanitizeText("a\tb"))
	// Bidirectional overrides, zero-width characters and Unicode line separators are neutralized too.
	assert.Equal(t, "a b c d e", sanitizeText("a\u202eb\u200bc\u2028d\u2066e"))
}

func TestProcessMessageSanitizesComponentRows(t *testing.T) {
	// Details and Mode of every component row are server text too.
	status := StatusMessage{
		Status: "Admin control mode.\x1b[2J",
		Components: &ComponentResults{
			Activation: &ComponentResult{Result: ComponentResultSuccess, Mode: "ACM\x1b[31m"},
			TLS: &ComponentResult{
				Result:  ComponentResultSuccess,
				Details: "Configured\nlevel=error msg=forged",
			},
		},
	}
	statusJSON, err := json.Marshal(status)
	assert.NoError(t, err)

	activation, err := json.Marshal(Message{Method: "success", Message: string(statusJSON)})
	assert.NoError(t, err)

	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	out := captureLogOutput(func() { server.ProcessMessage(activation) })
	assert.NotContains(t, out, "\x1b")
	assert.NotContains(t, out, "\nlevel=error msg=forged")
	assert.Contains(t, out, "Configured level=error msg=forged")
	assert.Nil(t, server.LastError)
}

func TestProcessMessageSuccessWithFailedComponentSetsExitCode(t *testing.T) {
	// Network, TLS and CIRA failures do not end the flow in RPS, so they arrive on "success":
	// the exit code still has to say that part of the configuration was not applied.
	cases := []struct {
		components ComponentResults
		expected   utils.CustomError
	}{
		{ComponentResults{WiredNetwork: &ComponentResult{Result: ComponentResultFailure, Code: "AMT_PT_INVALID_IP_ADDRESS"}}, utils.NetworkConfigurationFailed},
		{ComponentResults{WirelessNetwork: &ComponentResult{Result: ComponentResultFailure, Code: "AMT_PT_UNSUPPORTED"}}, utils.WiFiConfigurationFailed},
		{ComponentResults{TLS: &ComponentResult{Result: ComponentResultFailure, Code: "WSMAN_TIMEOUT"}}, utils.TLSConfigurationFailed},
		{ComponentResults{CIRAConnection: &ComponentResult{Result: ComponentResultFailure, Code: "AMT_PT_DUPLICATE"}}, utils.CIRAConfigurationFailed},
	}

	for _, tc := range cases {
		tc.components.Activation = &ComponentResult{Result: ComponentResultSuccess, Mode: "ACM"}
		statusJSON, err := json.Marshal(StatusMessage{Status: "Admin control mode.", Components: &tc.components})
		assert.NoError(t, err)

		activation, err := json.Marshal(Message{Method: "success", Message: string(statusJSON)})
		assert.NoError(t, err)

		server := NewAMTActivationServer(testFlags)
		server.Connect(true)
		server.ProcessMessage(activation)

		customErr, ok := server.LastError.(utils.CustomError)
		assert.True(t, ok)
		assert.Equal(t, tc.expected.Code, customErr.Code)
		assert.NotEmpty(t, customErr.Details)
	}
}

func TestProcessMessageErrorKeepsStatusTextAndNamesTheFlow(t *testing.T) {
	// A failed maintenance task keeps its task-specific Status text and is not called provisioning.
	status := StatusMessage{
		Status: "Failed to update AMT admin password",
		Error: &ProvisioningError{
			Code:      "WSMAN_AUTH_FAILED",
			Component: "Maintenance",
			Step:      "SET_ADMIN_ACL_ENTRY",
			Reason:    "AMT rejected the digest credentials (HTTP 401)",
		},
	}
	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	out := captureLogOutput(func() { server.ProcessMessage(errorMessage(t, status)) })
	assert.Contains(t, out, "Failed to update AMT admin password")
	assert.Contains(t, out, "Maintenance failed [Maintenance/SET_ADMIN_ACL_ENTRY] WSMAN_AUTH_FAILED")
	assert.NotContains(t, out, "Provisioning failed")

	assert.Equal(t, "Deactivation failed [Deactivation] RPS_DEACTIVATION_FAILED: Device deactivation failed",
		formatProvisioningError(&ProvisioningError{Code: "RPS_DEACTIVATION_FAILED", Component: "Deactivation", Reason: "Device deactivation failed"}))
}
