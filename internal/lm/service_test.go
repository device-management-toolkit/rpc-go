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

// TestListenPlainWaitsForDelayedResponse pins the plain-relay first-byte window
// against regression. The activating IPS_HostBasedSetupService/Setup response
// arrives after AMT runs its provisioning crypto — well past the old 500ms
// read timeout. With plainFirstByteTimeout (3s) the relay must still capture
// and forward that delayed response rather than timing out empty and closing
// the socket (which stranded the reply, made RPS retry Setup against an
// already-activated device, and reported "Failed to activate").
func TestListenPlainWaitsForDelayedResponse(t *testing.T) {
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

	go lms.Listen()

	// Respond well after the retired 500ms window but inside the 3s budget,
	// mimicking AMT's slow Setup reply.
	const afterOldTimeout = 900 * time.Millisecond

	go func() {
		time.Sleep(afterOldTimeout)

		_, err := client.Write([]byte("setup-response"))
		assert.NoError(t, err)

		client.Close()
	}()

	select {
	case got := <-data:
		assert.Equal(t, []byte("setup-response"), got)
	case err := <-errCh:
		t.Fatalf("plain relay abandoned the delayed response: %v", err)
	case <-time.After(plainFirstByteTimeout + time.Second):
		t.Fatal("Listen did not deliver the delayed response within the plain first-byte window")
	}
}

func TestStartTLSStreamForwardsChunksImmediately(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	lms := &LMSConnection{Connection: server, useTls: true}
	defer lms.Close()

	generation, events := lms.StartTLSStream()

	for _, chunk := range []string{"first", "second"} {
		written := time.Now()

		go func(c string) { _, _ = client.Write([]byte(c)) }(chunk)

		select {
		case event := <-events:
			assert.Equal(t, generation, event.Generation)
			assert.Equal(t, []byte(chunk), event.Data)
			assert.NoError(t, event.Err)
			assert.Less(t, time.Since(written), 500*time.Millisecond)
		case <-time.After(5 * time.Second):
			t.Fatalf("chunk %q was not forwarded", chunk)
		}
	}
}

func TestStartTLSStreamPeerCloseSignalsEOF(t *testing.T) {
	server, client := net.Pipe()

	lms := &LMSConnection{Connection: server, useTls: true}
	defer lms.Close()

	generation, events := lms.StartTLSStream()

	assert.NoError(t, client.Close())

	select {
	case event := <-events:
		assert.Equal(t, generation, event.Generation)
		assert.Empty(t, event.Data)
		assert.ErrorIs(t, event.Err, io.EOF)
	case <-time.After(5 * time.Second):
		t.Fatal("peer close was not signaled")
	}
}

func TestStartTLSStreamLocalCloseIsSilent(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	delayed := &delayedReadConn{Conn: server, entered: make(chan struct{}), release: make(chan struct{})}
	lms := &LMSConnection{Connection: delayed, useTls: true}
	_, events := lms.StartTLSStream()

	select {
	case <-delayed.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not start")
	}

	assert.NoError(t, lms.Close())
	close(delayed.release)

	select {
	case event := <-events:
		t.Fatalf("local close emitted an event: %v", event)
	case <-time.After(50 * time.Millisecond):
	}
}

// A successful emit that closes the local stream must not start another read.
func TestReadStreamStopsAfterEmit(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		readStream(server, stop, func(data []byte, err error) {
			assert.Equal(t, []byte("data"), data)
			assert.NoError(t, err)
			close(stop)
		})
		close(done)
	}()

	_, err := client.Write([]byte("data"))
	assert.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader started another read after local stop")
	}
}

// Hold an old socket's read result until the replacement is connected.
type delayedReadConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
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

func TestListenTLSBuffersHandshakeForOlderRPS(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	data := make(chan []byte)
	errCh := make(chan error, 1)
	local := &LMSConnection{Connection: server, useTls: true, data: data, errors: errCh}
	hello := []byte{0x16, 3, 3, 0, 1, 2}
	encrypted := []byte{0x17, 3, 3, 0, 1, 0}

	go local.Listen()

	_, err := client.Write(hello)
	assert.NoError(t, err)

	select {
	case <-data:
		t.Fatal("legacy reader forwarded ServerHello before the silence window")
	case <-time.After(100 * time.Millisecond):
	}

	_, err = client.Write(encrypted)
	assert.NoError(t, err)

	written := time.Now()

	select {
	case <-data:
		t.Fatal("legacy reader forwarded a separate encrypted handshake record")
	case <-time.After(300 * time.Millisecond):
	}

	select {
	case received := <-data:
		assert.Equal(t, append(hello, encrypted...), received)
		assert.GreaterOrEqual(t, time.Since(written), 900*time.Millisecond)
	case err := <-errCh:
		t.Fatalf("unexpected read error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("legacy reader did not flush the bundled handshake")
	}
}

func TestListenTLSQuietRoundDoesNotReset(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	data := make(chan []byte, 1)
	errCh := make(chan error, 1)
	local := &LMSConnection{Connection: server, useTls: true, data: data, errors: errCh}
	done := make(chan struct{})

	go func() { local.Listen(); close(done) }()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, ErrLMSReadTimeoutNoData)
	case <-time.After(5 * time.Second):
		t.Fatal("quiet TLS round did not report its typed timeout")
	}

	<-done
	assert.Empty(t, data)
}

func (c *delayedReadConn) Read(data []byte) (int, error) {
	close(c.entered)
	n, err := c.Conn.Read(data)
	<-c.release

	return n, err
}
