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
