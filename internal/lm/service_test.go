/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
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

// TestListenTLSTimeoutNoData verifies that when useTls is true and the
// first-byte read deadline expires before any bytes arrive, Listen sends
// ErrLMSReadTimeoutNoData on the errors channel and does NOT push an empty
// buffer onto the data channel.
func TestListenTLSTimeoutNoData(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	data := make(chan []byte, 1)
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

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, ErrLMSReadTimeoutNoData)
	case d := <-data:
		t.Fatalf("expected ErrLMSReadTimeoutNoData on errors channel, got data: %v", d)
	case <-time.After(5 * time.Second):
		t.Fatal("Listen did not return within timeout")
	}

	select {
	case d := <-data:
		t.Fatalf("expected no data, got: %v", d)
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Listen goroutine did not exit")
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
