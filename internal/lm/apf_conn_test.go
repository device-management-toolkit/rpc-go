/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package lm

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestAPFChannelConnReadDeadlineExceeded(t *testing.T) {
	conn := &APFChannelConn{
		incoming: make(chan []byte),
		closeCh:  make(chan struct{}),
	}

	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	buf := make([]byte, 8)

	n, err := conn.Read(buf)
	if n != 0 {
		t.Fatalf("Read() bytes = %d, want 0", n)
	}

	if err == nil {
		t.Fatal("Read() error = nil, want timeout error")
	}

	var timeoutErr interface{ Timeout() bool }
	if !errors.As(err, &timeoutErr) || !timeoutErr.Timeout() {
		t.Fatalf("Read() error = %v, want timeout=true", err)
	}
}

func TestAPFChannelConnReadLeftoverBuffering(t *testing.T) {
	incoming := make(chan []byte, 1)
	incoming <- []byte("abcdef")

	conn := &APFChannelConn{
		incoming: incoming,
		closeCh:  make(chan struct{}),
	}

	buf := make([]byte, 4)

	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}

	if got := string(buf[:n]); got != "abcd" {
		t.Fatalf("first Read() = %q, want %q", got, "abcd")
	}

	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}

	if got := string(buf[:n]); got != "ef" {
		t.Fatalf("second Read() = %q, want %q", got, "ef")
	}
}

func TestAPFChannelConnCloseUnblocksRead(t *testing.T) {
	conn := &APFChannelConn{
		incoming: make(chan []byte),
		closeCh:  make(chan struct{}),
	}

	started := make(chan struct{})
	result := make(chan error, 1)

	go func() {
		close(started)

		_, err := conn.Read(make([]byte, 1))
		result <- err
	}()

	<-started
	time.Sleep(10 * time.Millisecond)

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read() error after Close() = %v, want io.EOF", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Read() did not unblock after Close()")
	}
}
