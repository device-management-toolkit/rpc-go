/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		executor := Executor{localManagement: local, tlsTunnelActive: true, lmConnected: true, lmListening: true, streamGeneration: 2, tlsSessionID: "replacement"}
		// An attempted send would also fail because there is deliberately no server socket.
		executor.handleStreamedEvent(event)
		assert.Zero(t, local.closed)
		assert.True(t, executor.lmConnected)
		assert.True(t, executor.lmListening)
	}
}

func TestClientHelloReplacesGenerationBeforeOldEOF(t *testing.T) {
	local := &streamTestLM{generation: 2, events: make(chan lm.StreamEvent)}
	executor := Executor{localManagement: local, tlsTunnelActive: true, lmConnected: true, lmListening: true, streamGeneration: 2, tlsSessionID: "old"}
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
	executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, tlsTunnelActive: true, lmConnected: true, lmListening: true, streamGeneration: 7, tlsSessionID: "tls-session"}
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

			executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, tlsTunnelActive: true, lmConnected: writeFailure, lmListening: writeFailure, peerClosed: !writeFailure, tlsSessionID: "closed"}
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
	executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, data: data, errors: make(chan error), tlsTunnelActive: true, peerClosed: true, tlsSessionID: "closed"}
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

	stale, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: "closed", Payload: base64.StdEncoding.EncodeToString([]byte{0x17, 3, 3, 0, 1, 0})})
	require.NoError(t, err)
	assert.False(t, executor.HandleDataFromRPS(stale))
	assert.Empty(t, executor.tlsSessionID)
	assert.Zero(t, local.closed)
	assert.Equal(t, 1, local.connected)
	assert.Len(t, local.writes, 1)
}

func TestPortSwitchReplacesLMSWithSingleTLSReader(t *testing.T) {
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

	executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: &streamTestLM{}, tlsSessionID: "before-switch"}
	payload, err := json.Marshal(PortSwitchPayload{Port: port})
	assert.NoError(t, err)

	assert.NoError(t, executor.handlePortSwitch(string(payload)))
	defer executor.localManagement.Close()

	assert.False(t, executor.isLME)

	stale, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: "before-switch", Payload: base64.StdEncoding.EncodeToString([]byte{0x17, 3, 3, 0, 1, 0})})
	require.NoError(t, err)
	assert.False(t, executor.HandleDataFromRPS(stale))
	assert.Empty(t, executor.tlsSessionID)
	assert.False(t, executor.lmConnected)
	assert.Nil(t, executor.stream)

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
			executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, data: data, errors: make(chan error), tlsTunnelActive: true}
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

// v3 keeps LME on HECI after a port switch; v2 replaced it with an LMS
// socket. Porting that replacement would fail whenever LMS is absent.
func TestPortSwitchKeepsLMEHandle(t *testing.T) {
	conn, response, err := websocket.DefaultDialer.Dial(testUrl, nil)
	if response != nil {
		defer response.Body.Close()
	}

	require.NoError(t, err)

	defer conn.Close()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	device := &openTracker{open: true}
	local := lm.NewLMEConnection(make(chan []byte), make(chan error), &sync.WaitGroup{})
	local.Command = pthi.Command{Heci: device}
	executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, isLME: true}
	require.NoError(t, executor.handlePortSwitch(`{"port":"16993","delay":0}`))
	assert.Same(t, local, executor.localManagement)
	assert.True(t, device.open)
	assert.True(t, executor.isLME)
	assert.True(t, executor.tlsTunnelActive)
	assert.Nil(t, executor.stream)

	var ack Message
	require.NoError(t, conn.ReadJSON(&ack))
	assert.Equal(t, MethodPortSwitchAck, ack.Method)
}

// An established LME tunnel must retain its existing coalescing and quiet-round
// behavior even when a newer RPS includes the LMS streaming capability field.
func TestLMETunnelWithStreamingCapableRPS(t *testing.T) {
	for _, scenario := range []string{"response-and-close", "quiet-round", "read-error"} {
		t.Run(scenario, func(t *testing.T) {
			conn, response, err := websocket.DefaultDialer.Dial(testUrl, nil)
			if response != nil {
				defer response.Body.Close()
			}

			require.NoError(t, err)

			defer conn.Close()

			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

			data := make(chan []byte, 3)
			errs := make(chan error, 1)
			local := &streamTestLM{}
			executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, isLME: true, tlsTunnelActive: true, lmConnected: true, data: data, errors: errs}

			switch scenario {
			case "response-and-close":
				data <- []byte("first")

				data <- []byte("second")

				data <- nil
			case "quiet-round":
				errs <- lm.ErrLMSReadTimeoutNoData
			case "read-error":
				errs <- net.ErrClosed
			}

			request, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: "session", Payload: base64.StdEncoding.EncodeToString([]byte{0x17, 3, 3, 0, 1, 0})})
			require.NoError(t, err)
			assert.False(t, executor.HandleDataFromRPS(request))
			assert.NoError(t, executor.lastError)
			assert.Zero(t, local.closed, "LME must retain the HECI handle")
			assert.Zero(t, local.generation, "LME must not start an LMS streaming reader")
			assert.Len(t, local.writes, 1)
			assert.True(t, executor.isLME)

			if scenario == "quiet-round" {
				assert.True(t, executor.lmConnected)

				return
			}

			assert.False(t, executor.lmConnected)

			var forwarded Message
			require.NoError(t, conn.ReadJSON(&forwarded))

			if scenario == "response-and-close" {
				assert.Equal(t, MethodTLSData, forwarded.Method)
				assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("firstsecond")), forwarded.Payload)
			} else {
				assert.Equal(t, MethodConnectionReset, forwarded.Method)
			}
		})
	}
}

func TestLMEPlainRelayDoesNotSelectTLSStreaming(t *testing.T) {
	conn, response, err := websocket.DefaultDialer.Dial(testUrl, nil)
	if response != nil {
		defer response.Body.Close()
	}

	require.NoError(t, err)

	defer conn.Close()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	data := make(chan []byte)
	local := &streamTestLM{replyChannel: data, reply: []byte("plain response")}
	executor := Executor{server: AMTActivationServer{Conn: conn}, localManagement: local, isLME: true, data: data, errors: make(chan error)}
	request, err := json.Marshal(Message{Method: "wsman", Payload: base64.StdEncoding.EncodeToString([]byte("plain request"))})
	require.NoError(t, err)
	assert.False(t, executor.HandleDataFromRPS(request))
	assert.NoError(t, executor.lastError)
	assert.Zero(t, local.closed)
	assert.Zero(t, local.generation)
	assert.Equal(t, 1, local.listenCalls)
	assert.Equal(t, 1, local.connected)

	var forwarded Message
	require.NoError(t, conn.ReadJSON(&forwarded))
	assert.Equal(t, "response", forwarded.Method)
	assert.Equal(t, base64.StdEncoding.EncodeToString(local.reply), forwarded.Payload)
}

func TestRetiredTLSSessionCannotReplaceCurrentTunnel(t *testing.T) {
	for _, stalePayload := range [][]byte{
		{0x17, 3, 3, 0, 1, 0}, // delayed application data
		{0x16, 3, 3, 0, 1, 1}, // delayed ClientHello
	} {
		t.Run(fmt.Sprintf("record-%x", stalePayload[0]), func(t *testing.T) {
			local := &streamTestLM{events: make(chan lm.StreamEvent)}
			executor := Executor{localManagement: local, tlsTunnelActive: true}
			send := func(id string, payload []byte) {
				request, err := json.Marshal(Message{Method: MethodTLSData, TLSSessionID: id, Payload: base64.StdEncoding.EncodeToString(payload)})
				require.NoError(t, err)
				require.False(t, executor.HandleDataFromRPS(request))
			}
			hello := []byte{0x16, 3, 3, 0, 1, 1}
			send("A", hello)
			send("B", hello)

			generation, stream := executor.streamGeneration, executor.stream

			send("A", stalePayload)
			assert.Equal(t, "B", executor.tlsSessionID)
			assert.Equal(t, generation, executor.streamGeneration)
			assert.Equal(t, stream, executor.stream)
			assert.True(t, executor.lmConnected)
			assert.True(t, executor.lmListening)
			assert.False(t, executor.peerClosed)
			assert.Equal(t, 1, local.closed)
			assert.Equal(t, 2, local.connected)
			assert.Len(t, local.writes, 2)
			// B and ID-less continuation records still use the working tunnel.
			send("B", []byte{0x17, 3, 3, 0, 1, 2})
			send("", []byte{0x17, 3, 3, 0, 1, 3})
			assert.Equal(t, "B", executor.tlsSessionID)
			assert.Equal(t, generation, executor.streamGeneration)
			assert.Equal(t, 1, local.closed)
			assert.Equal(t, 2, local.connected)
			assert.Len(t, local.writes, 4)
		})
	}
}
