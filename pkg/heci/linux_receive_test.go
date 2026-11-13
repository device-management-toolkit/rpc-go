//go:build linux
// +build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package heci

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A pipe stands in for the MEI device: nothing is written, so the receive
// stays pending the way it does on a client that never answers.
func TestInterruptibleReceiveStopsOnClose(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)

	defer w.Close()

	h := &Driver{meiDevice: r, interruptible: true}

	done := make(chan error, 1)

	go func() {
		_, err := h.ReceiveMessage(make([]byte, 16), nil)
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	h.Close()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, os.ErrClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("receive still pending after Close")
	}
}

func TestInterruptibleReceiveReadsData(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)

	defer w.Close()

	h := &Driver{meiDevice: r, interruptible: true}
	defer h.Close()

	_, err = w.Write([]byte{1, 2, 3})
	require.NoError(t, err)

	buffer := make([]byte, 16)

	n, err := h.ReceiveMessage(buffer, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, buffer[:n])
}
