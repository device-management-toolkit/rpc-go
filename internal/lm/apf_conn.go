/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package lm

import (
	"io"
	"net"
	"sync"
	"time"
)

// APFChannelConn adapts an LMEConnection's currently-open APF channel to
// net.Conn so a tls.Client handshake (and subsequent encrypted writes/reads)
// can be layered over the APF data stream. It does not own the channel
// lifecycle: the caller is responsible for Connect()/OPEN_CONFIRMATION and
// for letting AMT's CHANNEL_CLOSE tear the channel down.
type APFChannelConn struct {
	lme      *LMEConnection
	incoming chan []byte

	readMu       sync.Mutex
	leftover     []byte
	closed       bool
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

	return &APFChannelConn{lme: lme, incoming: stream}
}

const lmeAPFStreamBuffer = 16

func (c *APFChannelConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]

		return n, nil
	}

	if c.closed {
		return 0, io.EOF
	}

	var (
		chunk []byte
		ok    bool
	)

	if c.readDeadline.IsZero() {
		chunk, ok = <-c.incoming
	} else {
		remaining := time.Until(c.readDeadline)
		if remaining <= 0 {
			return 0, apfDeadlineExceeded{}
		}

		t := time.NewTimer(remaining)
		defer t.Stop()

		select {
		case chunk, ok = <-c.incoming:
		case <-t.C:
			return 0, apfDeadlineExceeded{}
		}
	}

	if !ok {
		c.closed = true

		return 0, io.EOF
	}

	n := copy(p, chunk)
	if n < len(chunk) {
		c.leftover = chunk[n:]
	}

	return n, nil
}

func (c *APFChannelConn) Write(p []byte) (int, error) {
	if err := c.lme.Send(p); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *APFChannelConn) Close() error {
	c.readMu.Lock()
	c.closed = true
	c.readMu.Unlock()

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
