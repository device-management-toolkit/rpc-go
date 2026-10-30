/*********************************************************************
* Copyright (c) Intel Corporation 2021
* SPDX-License-Identifier: Apache-2.0
**********************************************************************/
package rps

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
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

// streamTestLM keeps executor tests independent of hardware socket timing.
type streamTestLM struct {
	generation   uint64
	events       chan lm.StreamEvent
	closed       int
	connected    int
	writes       [][]byte
	sendErr      error
	listenCalls  int
	replyChannel chan []byte
	reply        []byte
}

func (m *streamTestLM) Initialize() error { return nil }
func (m *streamTestLM) Connect() error {
	m.connected++

	return nil
}
func (m *streamTestLM) Listen() {
	m.listenCalls++
	if m.replyChannel != nil {
		m.replyChannel <- m.reply
	}
}
func (m *streamTestLM) Close() error {
	m.closed++

	return nil
}
func (m *streamTestLM) Send(data []byte) error {
	m.writes = append(m.writes, append([]byte(nil), data...))

	return m.sendErr
}
func (m *streamTestLM) StartTLSStream() (uint64, <-chan lm.StreamEvent) {
	m.generation++

	return m.generation, m.events
}

func TestObsoleteStreamEventsCannotResetReplacement(t *testing.T) {
	for _, event := range []lm.StreamEvent{
		{Generation: 1, Data: []byte("old bytes")},
		{Generation: 1, Err: io.EOF},
		{Generation: 1, Err: net.ErrClosed},
	} {
		local := &streamTestLM{}
		executor := Executor{localManagement: local, localTlsEnforced: true, lmConnected: true, lmListening: true, streamGeneration: 2, tlsSessionID: "replacement"}
		// An attempted send would also fail because there is deliberately no server socket.
		executor.handleStreamedEvent(event)
		assert.Zero(t, local.closed)
		assert.True(t, executor.lmConnected)
		assert.True(t, executor.lmListening)
	}
}

func TestClientHelloReplacesGenerationBeforeOldEOF(t *testing.T) {
	local := &streamTestLM{generation: 2, events: make(chan lm.StreamEvent)}
	executor := Executor{localManagement: local, localTlsEnforced: true, lmConnected: true, lmListening: true, streamGeneration: 2, tlsSessionID: "old"}
	request, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: "new", Payload: base64.StdEncoding.EncodeToString([]byte{0x16, 3, 3, 0, 1, 1})})
	assert.NoError(t, err)
	assert.False(t, executor.HandleDataFromRPS(request))
	assert.Equal(t, uint64(3), executor.streamGeneration)
	assert.Equal(t, "new", executor.tlsSessionID)
	assert.Equal(t, 1, local.closed)
	assert.Len(t, local.writes, 1)
	executor.handleStreamedEvent(lm.StreamEvent{Generation: 2, Err: io.EOF})
	assert.Equal(t, 1, local.closed)
	assert.True(t, executor.lmConnected)
}

func TestPartialBytesAreFollowedBySessionScopedEOF(t *testing.T) {
	conn, response, err := websocket.DefaultDialer.Dial(testUrl, nil)
	if response != nil {
		defer response.Body.Close()
	}

	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	assert.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	local := &streamTestLM{}
	executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, localTlsEnforced: true, lmConnected: true, lmListening: true, streamGeneration: 7, tlsSessionID: "tls-session"}
	executor.handleStreamedEvent(lm.StreamEvent{Generation: 7, Data: []byte{0x17, 3}})
	executor.handleStreamedEvent(lm.StreamEvent{Generation: 7, Err: io.EOF})

	var data, eof Message
	assert.NoError(t, conn.ReadJSON(&data))
	assert.NoError(t, conn.ReadJSON(&eof))
	assert.Equal(t, MethodTLSData, data.Method)
	assert.Equal(t, "tls-session", data.TLSSessionID)
	assert.Equal(t, MethodConnectionReset, eof.Method)
	assert.Equal(t, "tls-session", eof.TLSSessionID)
	assert.True(t, eof.StreamClosed)
	assert.Equal(t, 1, local.closed)
	assert.False(t, executor.lmConnected)
}

func TestClosedTLSRequestsWaitForNewSession(t *testing.T) {
	for _, failure := range []string{"closed", "write", "read"} {
		t.Run(failure, func(t *testing.T) {
			writeFailure := failure == "write"

			conn, response, err := websocket.DefaultDialer.Dial(testUrl, nil)
			if response != nil {
				defer response.Body.Close()
			}

			if err != nil {
				t.Fatal(err)
			}

			defer conn.Close()

			assert.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

			local := &streamTestLM{events: make(chan lm.StreamEvent)}

			executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, localTlsEnforced: true, lmConnected: writeFailure, lmListening: writeFailure, peerClosed: !writeFailure, tlsSessionID: "closed"}
			if failure == "read" {
				executor.peerClosed = false
				executor.handleStreamedEvent(lm.StreamEvent{Err: net.ErrClosed})

				var reset Message
				assert.NoError(t, conn.ReadJSON(&reset))
				assert.Equal(t, MethodConnectionReset, reset.Method)
				assert.Equal(t, "closed", reset.TLSSessionID)
				assert.False(t, reset.StreamClosed)
			}

			request, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: "closed", Payload: base64.StdEncoding.EncodeToString([]byte{0x17, 3, 3, 0, 1, 0})})
			assert.NoError(t, err)

			if writeFailure {
				local.sendErr = net.ErrClosed

				assert.False(t, executor.HandleDataFromRPS(request))

				var reset Message
				assert.NoError(t, conn.ReadJSON(&reset))
				assert.Equal(t, MethodConnectionReset, reset.Method)
				assert.Equal(t, "closed", reset.TLSSessionID)
				assert.False(t, reset.StreamClosed)
				assert.False(t, executor.lmConnected)
			}

			writes := len(local.writes)

			for _, sessionID := range []string{"closed", ""} {
				request, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: sessionID, Payload: base64.StdEncoding.EncodeToString([]byte{0x17, 3, 3, 0, 1, 0})})
				assert.NoError(t, err)
				assert.False(t, executor.HandleDataFromRPS(request))

				var reset Message
				assert.NoError(t, conn.ReadJSON(&reset))
				assert.Equal(t, MethodConnectionReset, reset.Method)
				assert.Equal(t, "closed", reset.TLSSessionID)
				assert.Equal(t, "closed", executor.tlsSessionID)
				assert.True(t, executor.peerClosed)
			}

			assert.Zero(t, local.connected)
			assert.Len(t, local.writes, writes)
			local.sendErr = nil
			hello, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: "new", Payload: base64.StdEncoding.EncodeToString([]byte{0x16, 3, 3, 0, 1, 1})})
			assert.NoError(t, err)
			assert.False(t, executor.HandleDataFromRPS(hello))
			assert.Equal(t, 1, local.connected)
			assert.Len(t, local.writes, writes+1)
			assert.False(t, executor.peerClosed)
		})
	}
}

func TestLegacyClientHelloSelectsBufferedReaderAfterStreamClosure(t *testing.T) {
	conn, response, err := websocket.DefaultDialer.Dial(testUrl, nil)
	if response != nil {
		defer response.Body.Close()
	}

	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	assert.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	data := make(chan []byte)
	local := &streamTestLM{replyChannel: data, reply: []byte{0x16, 3, 3, 0, 1, 2}}
	executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, data: data, errors: make(chan error), localTlsEnforced: true, peerClosed: true, tlsSessionID: "closed"}
	hello, err := json.Marshal(Message{Method: MethodTLSData, Payload: base64.StdEncoding.EncodeToString([]byte{0x16, 3, 3, 0, 1, 1})})
	assert.NoError(t, err)
	assert.False(t, executor.HandleDataFromRPS(hello))
	assert.Empty(t, executor.tlsSessionID)
	assert.False(t, executor.peerClosed)
	assert.Equal(t, 1, local.connected)
	assert.Equal(t, 1, local.listenCalls)
	assert.Zero(t, local.generation)
	assert.Len(t, local.writes, 1)

	var forwarded Message
	assert.NoError(t, conn.ReadJSON(&forwarded))
	assert.Equal(t, MethodTLSData, forwarded.Method)
	assert.Empty(t, forwarded.TLSSessionID)
	assert.Equal(t, base64.StdEncoding.EncodeToString(local.reply), forwarded.Payload)
}

func TestPortSwitchReplacesLMEWithSingleTLSReader(t *testing.T) {
	listenConfig := net.ListenConfig{}

	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, response, err := websocket.DefaultDialer.Dial(testUrl, nil)
	if response != nil {
		defer response.Body.Close()
	}

	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	assert.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	_, port, err := net.SplitHostPort(listener.Addr().String())
	assert.NoError(t, err)

	executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: &streamTestLM{}, isLME: true}
	payload, err := json.Marshal(PortSwitchPayload{Port: port})
	assert.NoError(t, err)

	assert.NoError(t, executor.handlePortSwitch(string(payload)))
	defer executor.localManagement.Close()

	assert.False(t, executor.isLME)

	hello, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: "new", Payload: base64.StdEncoding.EncodeToString([]byte{0x16, 3, 3, 0, 1, 1})})
	assert.NoError(t, err)
	assert.False(t, executor.HandleDataFromRPS(hello))
	assert.True(t, executor.lmListening)
	assert.NotNil(t, executor.stream)
	assert.NotZero(t, executor.streamGeneration)
}

func TestExecutorShutdownClosesPortSwitchReplacement(t *testing.T) {
	listenConfig := net.ListenConfig{}

	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	assert.NoError(t, err)

	helloBytes := []byte{0x16, 3, 3, 0, 1, 1}
	requestRead := make(chan struct{})
	peerResult := make(chan error, 1)

	go func() {
		probe, err := listener.Accept()
		if err != nil {
			peerResult <- err

			return
		}

		probe.Close()

		peer, err := listener.Accept()
		if err != nil {
			peerResult <- err

			return
		}
		defer peer.Close()

		peer.SetDeadline(time.Now().Add(5 * time.Second))

		buffer := make([]byte, len(helloBytes))
		if _, err := io.ReadFull(peer, buffer); err != nil {
			peerResult <- err

			return
		}

		close(requestRead)

		_, err = peer.Read(make([]byte, 1))
		peerResult <- err
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()

		ws.SetReadDeadline(time.Now().Add(5 * time.Second))

		var message Message
		if ws.ReadJSON(&message) != nil {
			return
		}

		payload, _ := json.Marshal(PortSwitchPayload{Port: port})
		ws.WriteJSON(Message{Method: MethodPortSwitch, Payload: string(payload)})

		if ws.ReadJSON(&message) != nil {
			return
		}

		ws.WriteJSON(Message{Method: MethodTLSData, TLSSessionID: "replacement", Payload: base64.StdEncoding.EncodeToString(helloBytes)})

		select {
		case <-requestRead:
			ws.WriteJSON(Message{Method: "success", Message: "configured"})
		case <-time.After(5 * time.Second):
		}
	}))
	defer server.Close()

	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if response != nil {
		defer response.Body.Close()
	}

	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	original := &streamTestLM{}
	executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: original, data: make(chan []byte), errors: make(chan error)}
	executor.MakeItSo(Message{Method: "activation"})
	assert.Equal(t, 1, original.closed)

	select {
	case err := <-peerResult:
		assert.ErrorIs(t, err, io.EOF)
	case <-time.After(6 * time.Second):
		t.Fatal("replacement socket did not close on executor shutdown")
	}
}

func TestTLSReaderSelectedByRPSSessionID(t *testing.T) {
	for _, sessionID := range []string{"", "streaming-session"} {
		t.Run("session="+sessionID, func(t *testing.T) {
			conn, response, err := websocket.DefaultDialer.Dial(testUrl, nil)
			if response != nil {
				defer response.Body.Close()
			}

			if err != nil {
				t.Fatal(err)
			}

			defer conn.Close()

			assert.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

			data := make(chan []byte)
			local := &streamTestLM{events: make(chan lm.StreamEvent), replyChannel: data, reply: []byte{0x16, 3, 3, 0, 1, 2, 0x17, 3, 3, 0, 1, 0}}
			executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, data: data, errors: make(chan error), localTlsEnforced: true}
			hello, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: sessionID, Payload: base64.StdEncoding.EncodeToString([]byte{0x16, 3, 3, 0, 1, 1})})
			assert.NoError(t, err)
			assert.False(t, executor.HandleDataFromRPS(hello))
			assert.Len(t, local.writes, 1)

			if sessionID == "" {
				assert.Equal(t, 1, local.listenCalls)
				assert.Zero(t, local.generation)
				assert.Nil(t, executor.stream)
			} else {
				assert.Zero(t, local.listenCalls)
				assert.Equal(t, uint64(1), local.generation)
				assert.NotNil(t, executor.stream)
				executor.handleStreamedEvent(lm.StreamEvent{Generation: 1, Data: local.reply})
			}

			var forwarded Message
			assert.NoError(t, conn.ReadJSON(&forwarded))
			assert.Equal(t, MethodTLSData, forwarded.Method)
			assert.Equal(t, sessionID, forwarded.TLSSessionID)
			assert.Equal(t, base64.StdEncoding.EncodeToString(local.reply), forwarded.Payload)

			if sessionID != "" {
				continuation, err := json.Marshal(Message{Method: MethodTLSData, Payload: base64.StdEncoding.EncodeToString([]byte{0x17, 3, 3, 0, 1, 0})})
				assert.NoError(t, err)
				assert.False(t, executor.HandleDataFromRPS(continuation))
				assert.Zero(t, local.listenCalls)
				assert.Equal(t, uint64(1), local.generation)
				assert.Equal(t, sessionID, executor.tlsSessionID)
			}
		})
	}
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
	// Older RPS without the Error block: single-line Status at error level. The run still fails.
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

	// An error message never exits 0, even without the structured Error block.
	customErr, ok := server.LastError.(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.GenericFailure.Code, customErr.Code)

	entry := logHook.LastEntry()
	assert.NotNil(t, entry)
	assert.Equal(t, log.ErrorLevel, entry.Level)
	assert.Equal(t, "Failed to add mps", entry.Message)
}

func TestProcessMessageErrorUnmarshalFailure(t *testing.T) {
	// Message is not Status JSON (e.g. a failure raised before the RPS state machine starts):
	// logged verbatim. The run still fails.
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

	// An error message never exits 0, even without the structured Error block.
	customErr, ok := server.LastError.(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.GenericFailure.Code, customErr.Code)

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
		formatProvisioningError(&ProvisioningError{Code: "WSMAN_TIMEOUT", Component: "TLS", Reason: "Timed out"}, ""))
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
		}, ""))
}

func TestFailureLabelForTimeSync(t *testing.T) {
	// Maintenance run: RPS reports time sync under TimeSync, so label it as maintenance.
	assert.Equal(t,
		"Maintenance failed [TimeSync/SYNC_TIME] WSMAN_TIMEOUT: Timed out",
		formatProvisioningError(&ProvisioningError{Code: "WSMAN_TIMEOUT", Component: "TimeSync", Step: "SYNC_TIME", Reason: "Timed out"}, utils.SubCommandSyncTime))
	assert.Equal(t,
		"Maintenance failed [TimeSync] WSMAN_TIMEOUT: Timed out",
		formatProvisioningError(&ProvisioningError{Code: "WSMAN_TIMEOUT", Component: "TimeSync", Reason: "Timed out"}, utils.SubCommandSyncClock))
	// Activation run: the same component is the clock step of provisioning.
	assert.Equal(t,
		"Provisioning failed [TimeSync] WSMAN_TIMEOUT: Timed out",
		formatProvisioningError(&ProvisioningError{Code: "WSMAN_TIMEOUT", Component: "TimeSync", Reason: "Timed out"}, ""))
}

func TestExitCodeForFailure(t *testing.T) {
	server := NewAMTActivationServer(testFlags)

	cases := map[string]utils.CustomError{
		"Activation":      utils.ActivationFailed,
		"WiredNetwork":    utils.WiredConfigurationFailed,
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
		}, ""))
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
		{ComponentResults{WiredNetwork: &ComponentResult{Result: ComponentResultFailure, Code: "AMT_PT_INVALID_IP_ADDRESS"}}, utils.WiredConfigurationFailed},
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
		formatProvisioningError(&ProvisioningError{Code: "RPS_DEACTIVATION_FAILED", Component: "Deactivation", Reason: "Device deactivation failed"}, ""))
}

func TestFailureSuffixNamesWsmanCallAndHTTPStatus(t *testing.T) {
	assert.Equal(t,
		" [WSMAN_BAD_REQUEST @ ADD_CERTIFICATE, AMT_PublicKeyManagementService.AddCertificate, HTTP 400]",
		failureSuffix(&ComponentResult{
			Code:       "WSMAN_BAD_REQUEST",
			Step:       "ADD_CERTIFICATE",
			WsmanCall:  "AMT_PublicKeyManagementService.AddCertificate",
			HttpStatus: intPtr(400),
		}))
}

func TestFailureExplanation(t *testing.T) {
	assert.Equal(t, "", failureExplanation(&ComponentResult{Details: "legacy"}))
	assert.Equal(t, "", failureExplanation(&ComponentResult{Details: "same", Reason: "same"}))
	assert.Equal(t, "Not supported", failureExplanation(&ComponentResult{Details: "Failed to add wifi", Reason: "Not supported"}))
	assert.Equal(t, "Timed out (Gateway Timeout)",
		failureExplanation(&ComponentResult{Details: "Failed", Reason: "Timed out", Detail: "Gateway Timeout"}))
	assert.Equal(t, "Gateway Timeout", failureExplanation(&ComponentResult{Details: "Failed", Detail: "Gateway Timeout"}))
}

// The message below is the JSON RPS serializes for a successful activation in which a Wi-Fi
// profile and the AMT features step failed. It checks the whole client side of the contract:
// decoding, the displayed diagnostics and the exit code.
func TestProcessMessageSuccessShowsFullComponentFailure(t *testing.T) {
	status := `{"Status":"Admin control mode.","Network":"Failed to add corp-wifi","Components":{` +
		`"Activation":{"Result":"Success","Mode":"ACM","Details":"Device activated in admin control mode"},` +
		`"WiredNetwork":{"Result":"NotApplicable","Details":"Wired network not part of this configuration"},` +
		`"WirelessNetwork":{"Result":"Failure","Details":"Failed to add corp-wifi","Code":"AMT_PT_UNSUPPORTED",` +
		`"Step":"ADD_WIFI_SETTINGS","AmtReturnValue":2066,` +
		`"Reason":"Operation or value is not supported by this AMT firmware",` +
		`"WsmanCall":"AMT_WiFiPortConfigurationService.AddWiFiSettings"},` +
		`"TLS":{"Result":"NotApplicable","Details":"TLS not part of this configuration"},` +
		`"CIRAProxy":{"Result":"NotApplicable","Details":"CIRA proxy not part of this configuration"},` +
		`"CIRAConnection":{"Result":"NotApplicable","Details":"CIRA connection not part of this configuration"},` +
		`"Features":{"Result":"Failure","Details":"Failed to get AMT redirection service","Code":"WSMAN_TIMEOUT",` +
		`"Step":"GET_AMT_REDIRECTION_SERVICE","Reason":"Timed out waiting for a WSMAN response from AMT",` +
		`"Detail":"Gateway Timeout"}}}`

	activation, err := json.Marshal(Message{Method: "success", Message: status})
	assert.NoError(t, err)

	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	out := captureLogOutput(func() { server.ProcessMessage(activation) })

	assert.Contains(t, out, "Wireless Network: Failed to add corp-wifi "+
		"[AMT_PT_UNSUPPORTED @ ADD_WIFI_SETTINGS, AMT_WiFiPortConfigurationService.AddWiFiSettings, ReturnValue 2066]")
	assert.Contains(t, out, "Operation or value is not supported by this AMT firmware")
	assert.Contains(t, out, "AMT Features:     Failed to get AMT redirection service [WSMAN_TIMEOUT @ GET_AMT_REDIRECTION_SERVICE]")
	assert.Contains(t, out, "Timed out waiting for a WSMAN response from AMT (Gateway Timeout)")

	// The first failed component decides the exit code.
	customErr, ok := server.LastError.(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.WiFiConfigurationFailed.Code, customErr.Code)
}

func TestProcessMessageSuccessWithFailedFeaturesOrUnconfigurationSetsExitCode(t *testing.T) {
	cases := []struct {
		components ComponentResults
		expected   utils.CustomError
	}{
		{ComponentResults{Features: &ComponentResult{Result: ComponentResultFailure, Code: "WSMAN_TIMEOUT"}}, utils.AMTFeaturesConfigurationFailed},
		{ComponentResults{Unconfiguration: &ComponentResult{Result: ComponentResultFailure, Code: "WSMAN_BAD_REQUEST"}}, utils.DeleteConfigsFailed},
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
	}
}

func TestExitCodeForUnstructuredErrorFollowsTheCommand(t *testing.T) {
	cases := []struct {
		command    string
		subCommand string
		expected   utils.CustomError
	}{
		{utils.CommandActivate, "", utils.ActivationFailed},
		{utils.CommandDeactivate, "", utils.DeactivationFailed},
		{utils.CommandMaintenance, utils.SubCommandSyncIP, utils.SyncIpFailed},
		{"", "", utils.GenericFailure},
	}

	for _, tc := range cases {
		f := flags.NewFlags([]string{}, MockPRSuccess)
		f.Command = tc.command
		f.SubCommand = tc.subCommand

		server := NewAMTActivationServer(f)
		assert.Equal(t, tc.expected.Code, server.exitCodeForUnstructuredError().Code)
	}
}

func TestExitCodeForUnstructuredErrorAfterCommandArgumentsAreAppended(t *testing.T) {
	// ExecuteCommand runs setCommandMethod first, which turns flags.Command into the full
	// command line sent to RPS (e.g. "activate --profile p1 -f").
	cases := []struct {
		command    string
		subCommand string
		expected   utils.CustomError
	}{
		{utils.CommandActivate, "", utils.ActivationFailed},
		{utils.CommandDeactivate, "", utils.DeactivationFailed},
		{utils.CommandMaintenance, utils.SubCommandSyncClock, utils.SyncClockFailed},
		{utils.CommandMaintenance, utils.SubCommandChangePassword, utils.ChangePasswordFailed},
	}

	for _, tc := range cases {
		f := flags.NewFlags([]string{}, MockPRSuccess)
		f.Command = tc.command
		f.SubCommand = tc.subCommand
		f.Profile = "p1"
		f.Password = "P@ssw0rd"
		f.StaticPassword = "N3wP@ssw0rd"
		f.Force = true

		setCommandMethod(f)
		assert.NotEqual(t, tc.command, f.Command)

		server := NewAMTActivationServer(f)
		assert.Equal(t, tc.expected.Code, server.exitCodeForUnstructuredError().Code)
	}
}

func TestProcessMessageSuccessWithFailedSharedNetworkStep(t *testing.T) {
	// The shared network setup runs before RPS knows which interfaces the device has, so its
	// failure is reported as Network rather than blamed on the wired or wireless component.
	components := ComponentResults{
		Activation: &ComponentResult{Result: ComponentResultSuccess, Mode: "ACM"},
		Network: &ComponentResult{
			Result:  ComponentResultFailure,
			Details: "Failed to update amt general settings on device",
			Code:    "WSMAN_TIMEOUT",
			Step:    "PUT_GENERAL_SETTINGS",
		},
	}
	statusJSON, err := json.Marshal(StatusMessage{Status: "Admin control mode.", Components: &components})
	assert.NoError(t, err)

	activation, err := json.Marshal(Message{Method: "success", Message: string(statusJSON)})
	assert.NoError(t, err)

	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	out := captureLogOutput(func() { server.ProcessMessage(activation) })
	assert.Contains(t, out, "Network:    Failed to update amt general settings on device [WSMAN_TIMEOUT @ PUT_GENERAL_SETTINGS]")
	// The same failure on one line, in the format used when the whole flow fails.
	assert.Contains(t, out, "Provisioning failed [Network/PUT_GENERAL_SETTINGS] WSMAN_TIMEOUT: Failed to update amt general settings on device")

	customErr, ok := server.LastError.(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.NetworkConfigurationFailed.Code, customErr.Code)
}

func TestProcessMessageSuccessWithSeveralFailedComponents(t *testing.T) {
	// One process has one exit code: the first failed component in summary order sets it and gets
	// the one-line summary, while every failure keeps its own row.
	status401 := 401
	components := ComponentResults{
		Activation: &ComponentResult{Result: ComponentResultSuccess, Mode: "ACM"},
		CIRAConnection: &ComponentResult{
			Result:     ComponentResultFailure,
			Details:    "Failed to set user initiated connection service",
			Code:       "WSMAN_AUTH_FAILED",
			Step:       "USER_INITIATED_CONNECTION_SERVICE",
			Reason:     "AMT rejected the digest credentials (HTTP 401)",
			HttpStatus: &status401,
			WsmanCall:  "AMT_UserInitiatedConnectionService.RequestStateChange",
		},
		Features: &ComponentResult{
			Result:  ComponentResultFailure,
			Details: "Failed to set redirection service",
			Code:    "WSMAN_AUTH_FAILED",
			Step:    "SET_REDIRECTION_SERVICE",
		},
	}
	statusJSON, err := json.Marshal(StatusMessage{Status: "Admin control mode.", Components: &components})
	assert.NoError(t, err)

	activation, err := json.Marshal(Message{Method: "success", Message: string(statusJSON)})
	assert.NoError(t, err)

	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	out := captureLogOutput(func() { server.ProcessMessage(activation) })
	assert.Contains(t, out, "Failed to set user initiated connection service [WSMAN_AUTH_FAILED @ USER_INITIATED_CONNECTION_SERVICE")
	assert.Contains(t, out, "Failed to set redirection service [WSMAN_AUTH_FAILED @ SET_REDIRECTION_SERVICE]")
	assert.Contains(t, out, "Provisioning failed [CIRAConnection/USER_INITIATED_CONNECTION_SERVICE] WSMAN_AUTH_FAILED: AMT rejected the digest credentials (HTTP 401) (AMT_UserInitiatedConnectionService.RequestStateChange; HTTP 401)")
	assert.Equal(t, 1, strings.Count(out, "Provisioning failed ["))

	customErr, ok := server.LastError.(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.CIRAConfigurationFailed.Code, customErr.Code)
}

func TestProcessMessageSuccessWithFailedComponentFromOlderRPS(t *testing.T) {
	// An RPS release without failure codes: the row is shown and the exit code is set, but there is
	// no code or step to build the one-line summary from.
	components := ComponentResults{
		Activation: &ComponentResult{Result: ComponentResultSuccess, Mode: "ACM"},
		TLS:        &ComponentResult{Result: ComponentResultFailure, Details: "Failed to configure TLS"},
	}
	statusJSON, err := json.Marshal(StatusMessage{Status: "Admin control mode.", Components: &components})
	assert.NoError(t, err)

	activation, err := json.Marshal(Message{Method: "success", Message: string(statusJSON)})
	assert.NoError(t, err)

	server := NewAMTActivationServer(testFlags)
	server.Connect(true)

	out := captureLogOutput(func() { server.ProcessMessage(activation) })
	assert.Contains(t, out, "Failed to configure TLS")
	assert.NotContains(t, out, "Provisioning failed [")

	customErr, ok := server.LastError.(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.TLSConfigurationFailed.Code, customErr.Code)
}

func TestProcessMessageErrorWithoutStatusLogsTheMessage(t *testing.T) {
	// Valid JSON with no Status and no Error block must not log an empty line.
	for _, message := range []string{"{\"message\":\"unauthorized\"}", "null"} {
		payload, err := json.Marshal(Message{Method: "error", Message: message})
		assert.NoError(t, err)

		server := NewAMTActivationServer(testFlags)
		server.Connect(true)

		logHook := test.NewGlobal()

		assert.Nil(t, server.ProcessMessage(payload))
		assert.Equal(t, message, logHook.LastEntry().Message)
		assert.NotNil(t, server.LastError)
		logHook.Reset()
	}
}

func TestSessionResult(t *testing.T) {
	newExecutor := func(command string) *Executor {
		f := flags.NewFlags([]string{}, MockPRSuccess)
		f.Command = command

		return &Executor{server: NewAMTActivationServer(f)}
	}

	t.Run("a failure RPS reported wins", func(t *testing.T) {
		e := newExecutor(utils.CommandActivate)
		e.server.LastError = utils.TLSConfigurationFailed
		e.server.Completed = true
		e.abortErr = utils.AMTConnectionFailed
		assert.Equal(t, utils.TLSConfigurationFailed, e.sessionResult())
	})

	t.Run("a completed run with no failure succeeds", func(t *testing.T) {
		e := newExecutor(utils.CommandActivate)
		e.server.Completed = true
		assert.NoError(t, e.sessionResult())
	})

	t.Run("an LMS failure on this side is reported as such", func(t *testing.T) {
		e := newExecutor(utils.CommandActivate)
		e.abortErr = utils.AMTConnectionFailed
		assert.Equal(t, utils.AMTConnectionFailed, e.sessionResult())
	})

	t.Run("a session that ends with no result fails with the code of the command", func(t *testing.T) {
		for command, expected := range map[string]utils.CustomError{
			utils.CommandActivate:   utils.ActivationFailed,
			utils.CommandDeactivate: utils.DeactivationFailed,
			"":                      utils.GenericFailure,
		} {
			customErr, ok := newExecutor(command).sessionResult().(utils.CustomError)
			assert.True(t, ok)
			assert.Equal(t, expected.Code, customErr.Code)
			assert.Equal(t, "session ended before RPS reported a result", customErr.Details)
		}
	})
}

func TestMakeItSoFailsWhenRPSClosesBeforeAResult(t *testing.T) {
	// RPS accepts the request and then goes away without a final success or error message.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		var message Message

		_ = ws.ReadJSON(&message)
		ws.Close()
	}))
	defer server.Close()

	run := func(command string) error {
		conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
		if response != nil {
			defer response.Body.Close()
		}

		if err != nil {
			t.Fatal(err)
		}

		defer conn.Close()

		f := flags.NewFlags([]string{}, MockPRSuccess)
		f.Command = command

		executor := Executor{
			server:          AMTActivationServer{Conn: conn, flags: f},
			localManagement: &streamTestLM{},
			data:            make(chan []byte),
			errors:          make(chan error),
		}

		return executor.MakeItSo(Message{Method: "activation"})
	}

	customErr, ok := run(utils.CommandActivate).(utils.CustomError)
	assert.True(t, ok)
	assert.Equal(t, utils.ActivationFailed.Code, customErr.Code)
}

func TestMakeItSoSucceedsAfterTheFinalSuccessMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		defer ws.Close()

		var message Message

		_ = ws.ReadJSON(&message)
		_ = ws.WriteJSON(Message{Method: "success", Message: "configured"})
	}))
	defer server.Close()

	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if response != nil {
		defer response.Body.Close()
	}

	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	executor := Executor{
		server:          AMTActivationServer{Conn: conn},
		localManagement: &streamTestLM{},
		data:            make(chan []byte),
		errors:          make(chan error),
	}
	assert.NoError(t, executor.MakeItSo(Message{Method: "activation"}))
}
