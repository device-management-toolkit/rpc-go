/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewLMSConnection(t *testing.T) {
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	lme := NewLMSConnection("::1", "16992", false, lmDataChannel, lmErrorChannel, 0, true)
	defer lme.Close()

	assert.Equal(t, lmDataChannel, lme.data)
	assert.Equal(t, lmErrorChannel, lme.errors)
	assert.Equal(t, "::1", lme.address)
	assert.Equal(t, "16992", lme.port)
}

func TestInitialize(t *testing.T) {
	_, client := net.Pipe()
	lms := LMSConnection{address: "", port: "", Connection: client}
	err := lms.Initialize()

	defer lms.Close()

	assert.Error(t, err)
}

func TestConnect(t *testing.T) {
	_, client := net.Pipe()
	lms := LMSConnection{address: "", port: "", Connection: client}
	err := lms.Connect()

	defer lms.Close()

	assert.NoError(t, err)
}

func TestSend(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	lms := LMSConnection{Connection: client}
	defer lms.Close() // should close client pipe

	go func() {
		err := lms.Send([]byte("data"))
		assert.NoError(t, err)
	}()
	// var b
	buff := make([]byte, 65535)
	n, err := server.Read(buff)
	assert.Equal(t, []byte("data"), buff[:n])
	assert.Greater(t, n, 0)
	assert.NoError(t, err)
}

func TestListen(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	wait2 := make(chan bool)
	data := make(chan []byte)
	errCh := make(chan error)
	lms := &LMSConnection{
		Connection: server,
		data:       data,
		errors:     errCh,
	}

	go func() {
		for {
			data := <-lms.data
			if len(data) > 0 {
				assert.Equal(t, []byte("data"), data)

				wait2 <- true

				break
			}
		}
	}()

	go lms.Listen()

	_, err := client.Write([]byte("data"))
	assert.NoError(t, err)

	<-wait2
	lms.Close() // should close client pipe
}

// TestListenTLSStreamsChunksImmediately verifies that in TLS-tunnel mode Listen forwards
// each chunk as soon as it is read instead of waiting for a silence gap, and keeps reading.
func TestListenTLSStreamsChunksImmediately(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	data := make(chan []byte, 4)
	errCh := make(chan error, 1)
	lms := &LMSConnection{
		Connection: server,
		useTls:     true,
		data:       data,
		errors:     errCh,
	}

	go lms.Listen()

	for _, chunk := range []string{"first", "second"} {
		written := time.Now()

		go func(c string) {
			_, _ = client.Write([]byte(c))
		}(chunk)

		select {
		case d := <-data:
			assert.Equal(t, []byte(chunk), d)
			assert.Less(t, time.Since(written), 500*time.Millisecond, "chunk must be forwarded without a silence wait")
		case err := <-errCh:
			t.Fatalf("unexpected error: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatalf("chunk %q was not forwarded", chunk)
		}

		time.Sleep(300 * time.Millisecond) // longer than any former silence window; reader must still be alive
	}
}

// TestListenTLSPeerCloseSignalsEmptyBuffer verifies that when AMT closes the tunnel
// connection the reader delivers an empty buffer (the executor's connection_reset trigger)
// and exits.
func TestListenTLSPeerCloseSignalsEmptyBuffer(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	data := make(chan []byte, 2)
	errCh := make(chan error, 1)
	lms := &LMSConnection{
		Connection: server,
		useTls:     true,
		data:       data,
		errors:     errCh,
	}

	done := make(chan struct{})

	go func() {
		lms.Listen()
		close(done)
	}()

	client.Close()

	select {
	case d := <-data:
		assert.Equal(t, 0, len(d))
	case err := <-errCh:
		t.Fatalf("expected empty data on peer close, got error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("peer close was not signaled")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Listen goroutine did not exit after peer close")
	}
}

// TestListenTLSLocalCloseIsSilent verifies that a deliberate Close() (port switch, new
// handshake, shutdown) ends the reader without signaling an error or a peer close.
func TestListenTLSLocalCloseIsSilent(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	data := make(chan []byte, 2)
	errCh := make(chan error, 1)
	lms := &LMSConnection{
		Connection: server,
		useTls:     true,
		data:       data,
		errors:     errCh,
	}

	done := make(chan struct{})

	go func() {
		lms.Listen()
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	assert.NoError(t, lms.Close())

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Listen goroutine did not exit after local close")
	}

	select {
	case d := <-data:
		t.Fatalf("expected nothing on the data channel after a local close, got %v", d)
	case err := <-errCh:
		t.Fatalf("expected nothing on the errors channel after a local close, got %v", err)
	default:
	}
}

// TestListenNonTLSTimeoutSendsEmptyBuf verifies that in non-TLS mode the
// existing behavior is preserved: a first-byte timeout still flushes the
// (empty) buffer onto the data channel and does NOT emit the typed sentinel.
func TestListenNonTLSTimeoutSendsEmptyBuf(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	data := make(chan []byte, 1)
	errCh := make(chan error, 1)
	lms := &LMSConnection{
		Connection: server,
		useTls:     false,
		data:       data,
		errors:     errCh,
	}

	done := make(chan struct{})

	go func() {
		lms.Listen()
		close(done)
	}()

	select {
	case d := <-data:
		assert.Equal(t, 0, len(d))
	case err := <-errCh:
		t.Fatalf("expected empty data on data channel, got error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Listen did not return within timeout")
	}

	select {
	case err := <-errCh:
		t.Fatalf("expected no error, got: %v", err)
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Listen goroutine did not exit")
	}
}

// Hold an old socket's read result until the replacement is connected.
type delayedReadConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
}

func (c *delayedReadConn) Read(data []byte) (int, error) {
	close(c.entered)
	n, err := c.Conn.Read(data)
	<-c.release

	return n, err
}

func TestOldReaderCloseCannotAffectReconnectedSocket(t *testing.T) {
	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	oldSocket, oldPeer := net.Pipe()
	defer oldPeer.Close()

	delayed := &delayedReadConn{Conn: oldSocket, entered: make(chan struct{}), release: make(chan struct{})}
	address := listener.Addr().(*net.TCPAddr)
	lms := NewLMSConnection("127.0.0.1", fmt.Sprint(address.Port), true, nil, nil, 0, false)
	lms.Connection = delayed
	oldGeneration, _ := lms.StartTLSStream()

	select {
	case <-delayed.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("old reader did not start")
	}

	assert.NoError(t, lms.Close())

	assert.NoError(t, lms.Connect())
	defer lms.Close()

	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	generation, events := lms.StartTLSStream()
	assert.Greater(t, generation, oldGeneration)
	close(delayed.release)

	_, err = peer.Write([]byte("replacement data"))
	assert.NoError(t, err)

	select {
	case event := <-events:
		assert.Equal(t, generation, event.Generation)
		assert.Equal(t, []byte("replacement data"), event.Data)
		assert.NoError(t, event.Err)
	case <-time.After(5 * time.Second):
		t.Fatal("replacement reader did not forward data")
	}
}

func TestStreamKeepsFinalBytesBeforeEOF(t *testing.T) {
	socket, peer := net.Pipe()

	lms := &LMSConnection{Connection: socket, useTls: true}
	defer lms.Close()

	generation, events := lms.StartTLSStream()

	go func() { _, _ = peer.Write([]byte("partial TLS record")); _ = peer.Close() }()

	for _, expectEOF := range []bool{false, true} {
		select {
		case event := <-events:
			assert.Equal(t, generation, event.Generation)

			if expectEOF {
				assert.ErrorIs(t, event.Err, io.EOF)
			} else {
				assert.Equal(t, []byte("partial TLS record"), event.Data)
				assert.NoError(t, event.Err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stream event not delivered")
		}
	}
}
