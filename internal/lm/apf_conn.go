/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package lm

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// APFChannelConn adapts an LMEConnection's currently-open APF channel to
// net.Conn so a tls.Client handshake (and subsequent encrypted writes/reads)
// can be layered over the APF data stream. It does not own the channel
// lifecycle: the caller is responsible for Connect()/OPEN_CONFIRMATION and
// for letting AMT's CHANNEL_CLOSE tear the channel down.
type APFChannelConn struct {
	lme       *LMEConnection
	incoming  chan []byte
	closeCh   chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once

	readMu       sync.Mutex
	leftover     []byte
	readDeadline time.Time
}

// NewAPFChannelConn enables streaming mode on the active LME session (so each
// APF_CHANNEL_DATA chunk is delivered to a channel rather than buffered into
// Tempdata until CHANNEL_CLOSE) and returns a net.Conn whose Read pops from
// that channel and whose Write frames bytes as APF_CHANNEL_DATA on the open
// channel via LMEConnection.Send.
func NewAPFChannelConn(lme *LMEConnection) *APFChannelConn {
	stream := make(chan []byte, lmeAPFStreamBuffer)
	lme.EnableTunnel(stream)

	return &APFChannelConn{lme: lme, incoming: stream, closeCh: make(chan struct{})}
}

const lmeAPFStreamBuffer = 16

func (c *APFChannelConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	if c.closeCh == nil {
		c.closeCh = make(chan struct{})
	}

	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		c.readMu.Unlock()

		return n, nil
	}

	if c.closed.Load() {
		c.readMu.Unlock()

		return 0, io.EOF
	}

	readDeadline := c.readDeadline
	incoming := c.incoming
	closeCh := c.closeCh
	c.readMu.Unlock()

	var (
		chunk []byte
		ok    bool
	)

	if readDeadline.IsZero() {
		select {
		case chunk, ok = <-incoming:
		case <-closeCh:
			return 0, io.EOF
		}
	} else {
		remaining := time.Until(readDeadline)
		if remaining <= 0 {
			return 0, apfDeadlineExceeded{}
		}

		t := time.NewTimer(remaining)
		select {
		case chunk, ok = <-incoming:
			t.Stop()
		case <-closeCh:
			t.Stop()

			return 0, io.EOF
		case <-t.C:
			return 0, apfDeadlineExceeded{}
		}
	}

	if !ok {
		c.closed.Store(true)

		return 0, io.EOF
	}

	c.readMu.Lock()
	if c.closed.Load() {
		c.readMu.Unlock()

		return 0, io.EOF
	}

	n := copy(p, chunk)
	if n < len(chunk) {
		c.leftover = chunk[n:]
	}
	c.readMu.Unlock()

	return n, nil
}

func (c *APFChannelConn) Write(p []byte) (int, error) {
	if c.lme == nil {
		return 0, errors.New("nil LME connection")
	}

	if err := c.lme.Send(p); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *APFChannelConn) Close() error {
	c.closed.Store(true)

	c.readMu.Lock()
	if c.closeCh == nil {
		c.closeCh = make(chan struct{})
	}

	closeCh := c.closeCh
	c.readMu.Unlock()

	c.closeOnce.Do(func() {
		close(closeCh)
	})

	return nil
}

func (c *APFChannelConn) LocalAddr() net.Addr  { return apfAddr{} }
func (c *APFChannelConn) RemoteAddr() net.Addr { return apfAddr{} }

func (c *APFChannelConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *APFChannelConn) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	c.readDeadline = t
	c.readMu.Unlock()

	return nil
}

// SetWriteDeadline is a no-op: APF writes go through HECI which enforces its
// own timeouts; we don't layer another deadline on top.
func (c *APFChannelConn) SetWriteDeadline(time.Time) error { return nil }

type apfAddr struct{}

func (apfAddr) Network() string { return "apf" }
func (apfAddr) String() string  { return "amt-apf-channel" }

type apfDeadlineExceeded struct{}

func (apfDeadlineExceeded) Error() string   { return "apf channel read deadline exceeded" }
func (apfDeadlineExceeded) Timeout() bool   { return true }
func (apfDeadlineExceeded) Temporary() bool { return true }
