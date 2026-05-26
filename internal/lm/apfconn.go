/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/apf"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// channelDataHeaderLen is the APF_CHANNEL_DATA framing prefix: type(1) +
// recipient channel(4) + data length(4). The payload follows.
const channelDataHeaderLen = 9

// apfOpenSlackSeconds is added to the HECI read timeout when bounding the open
// handshake, giving the read pump at least one full Receive cycle to surface a
// confirmation before Dial gives up.
const apfOpenSlackSeconds = 5

// apfOpenTimeout bounds the wait for APF_CHANNEL_OPEN_CONFIRMATION.
var apfOpenTimeout = (utils.HeciReadTimeout + apfOpenSlackSeconds) * time.Second

// apfChannelDataHeader is the fixed prefix of an APF_CHANNEL_DATA message,
// decoded to locate the payload without hand-coded byte offsets.
type apfChannelDataHeader struct {
	MessageType byte
	Recipient   uint32
	Length      uint32
}

// errChannelClosed is returned to readers/writers once the APF channel is closed
// locally (Close) without AMT having closed it first.
var errChannelClosed = errors.New("apf channel closed")

// APFConn is a streaming net.Conn over a single APF forwarded-tcpip channel
// carried on the HECI/MEI driver. Unlike LMEConnection (which batches a whole
// HTTP response and flushes it on APF_CHANNEL_CLOSE), APFConn delivers received
// CHANNEL_DATA payloads to readers immediately, so a multi-round-trip protocol
// such as a TLS handshake can run over it. Wrap it with tls.Client to reach AMT
// on the TLS local port (16993).
//
// A single read-pump goroutine owns cmd.Receive(); all sends (channel data,
// window adjust, keepalive reply, channel close) are serialized through writeMu.
// APFConn does NOT own the HECI handle — the caller that constructs cmd is
// responsible for closing it (and may close it to interrupt a stuck read pump).
type APFConn struct {
	cmd      pthi.Command
	sender   uint32 // our channel id, sent in APF_CHANNEL_OPEN
	port     uint32 // AMT-side port this channel targets
	maxChunk int    // largest CHANNEL_DATA payload we will send in one frame

	writeMu sync.Mutex // serializes cmd.Send across the pump and Write

	// amtCh is AMT's channel id (the recipient of our outgoing frames). It is set
	// once from the open confirmation, before openCh is signaled, so reads that
	// happen-after the Dial handshake (Write, the pump itself) see it safely.
	amtCh       atomic.Uint32
	established atomic.Bool

	// TX flow control: txWindow is the credit AMT has granted us. awaitWindow
	// blocks until it is non-zero (or the conn is closed / write deadline fires).
	txMu     sync.Mutex
	txWindow uint32
	txNotify chan struct{}

	// RX buffering: the pump appends decoded payloads to rxBuf and pokes rxNotify;
	// Read drains rxBuf. Buffering (rather than blocking the pump on delivery)
	// keeps window-adjust processing from deadlocking against a consumer that is
	// mid-Write waiting on TX credit.
	rxMu     sync.Mutex
	rxBuf    []byte
	rxErr    error
	rxNotify chan struct{}

	openCh    chan error
	closeReq  chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	readDeadline  connDeadline
	writeDeadline connDeadline
}

// DialAPF opens an APF forwarded-tcpip channel to the given AMT port over cmd's
// already-initialized HECI/LME session and returns it as a net.Conn. cmd must
// have completed the APF protocol handshake (see LMEConnection.Initialize).
func DialAPF(cmd pthi.Command, senderCh int, port uint32) (*APFConn, error) {
	bufSize := int(cmd.Heci.GetBufferSize())

	maxChunk := apf.LME_RX_WINDOW_SIZE
	if room := bufSize - channelDataHeaderLen; room > 0 && room < maxChunk {
		maxChunk = room
	}

	c := &APFConn{
		cmd:           cmd,
		sender:        uint32(senderCh),
		port:          port,
		maxChunk:      maxChunk,
		txNotify:      make(chan struct{}, 1),
		rxNotify:      make(chan struct{}, 1),
		openCh:        make(chan error, 1),
		closeReq:      make(chan struct{}),
		done:          make(chan struct{}),
		readDeadline:  makeConnDeadline(),
		writeDeadline: makeConnDeadline(),
	}

	openMsg := apf.ChannelOpenPort(senderCh, port)
	if err := c.sendRaw(openMsg.Bytes()); err != nil {
		return nil, fmt.Errorf("apf channel open: %w", err)
	}

	go c.readPump()

	select {
	case err := <-c.openCh:
		if err != nil {
			_ = c.Close()

			return nil, err
		}

		return c, nil
	case <-time.After(apfOpenTimeout):
		_ = c.Close()

		return nil, fmt.Errorf("timed out waiting for APF channel open after %s", apfOpenTimeout)
	}
}

// readPump is the sole owner of cmd.Receive(); it decodes APF messages until the
// channel closes or a non-timeout HECI error occurs, then exits.
func (c *APFConn) readPump() {
	defer close(c.done)

	for {
		select {
		case <-c.closeReq:
			return
		default:
		}

		result, n, err := c.cmd.Receive()
		if err != nil {
			if errors.Is(err, heci.ErrReadTimeout) {
				continue // ME idle; quiet TLS rounds are normal, keep waiting.
			}

			c.failRX(err)

			return
		}

		if n == 0 {
			c.failRX(io.EOF)

			return
		}

		if done := c.dispatch(result[:n]); done {
			return
		}
	}
}

// dispatch handles one decoded APF message and reports whether the pump should
// exit (channel closed or open failed).
func (c *APFConn) dispatch(msg []byte) (done bool) {
	log.Tracef("apfconn: received APF message type %d", msg[0])

	switch msg[0] {
	case apf.APF_CHANNEL_OPEN_CONFIRMATION:
		c.onOpenConfirmation(msg)
	case apf.APF_CHANNEL_OPEN_FAILURE:
		err := c.onOpenFailure(msg)
		c.signalOpen(err)
		c.failRX(err)

		return true
	case apf.APF_CHANNEL_DATA:
		c.onChannelData(msg)
	case apf.APF_CHANNEL_WINDOW_ADJUST:
		c.onWindowAdjust(msg)
	case apf.APF_CHANNEL_CLOSE:
		c.failRX(io.EOF)

		return true
	case apf.APF_GLOBAL_REQUEST:
		c.onGlobalRequest(msg)
	case apf.APF_KEEPALIVE_REQUEST:
		c.onKeepAlive(msg)
	default:
		log.Tracef("apfconn: ignoring APF message type %d", msg[0])
	}

	return false
}

// onGlobalRequest replies to AMT's tcpip-forward advertisements. AMT sets
// WantReply on these and stalls subsequent channel opens if they go unanswered,
// so the channel pump must echo the success reply just as the init handshake
// does — otherwise the first channel works but the next one hangs.
func (c *APFConn) onGlobalRequest(msg []byte) {
	if !apf.ValidateGlobalRequest(msg) {
		return
	}

	_, reply := apf.ProcessGlobalRequest(msg)
	if reply == nil {
		return
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, reply); err != nil {
		log.Tracef("apfconn: encode global request reply: %v", err)

		return
	}

	if err := c.sendRaw(buf.Bytes()); err != nil {
		log.Tracef("apfconn: global request reply send failed: %v", err)
	}
}

func (c *APFConn) onOpenConfirmation(msg []byte) {
	var conf apf.APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE
	if err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &conf); err != nil {
		c.signalOpen(fmt.Errorf("decode open confirmation: %w", err))

		return
	}

	c.amtCh.Store(conf.SenderChannel)
	c.setTXWindow(conf.InitialWindowSize)
	c.established.Store(true)
	c.signalOpen(nil)
}

func (c *APFConn) onOpenFailure(msg []byte) error {
	var fail apf.APF_CHANNEL_OPEN_FAILURE_MESSAGE
	if err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &fail); err != nil {
		return fmt.Errorf("decode open failure: %w", err)
	}

	return fmt.Errorf("apf channel open failed, reason code %d", fail.ReasonCode)
}

func (c *APFConn) onChannelData(msg []byte) {
	var hdr apfChannelDataHeader
	if err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &hdr); err != nil {
		return
	}

	end := channelDataHeaderLen + int(hdr.Length)
	if hdr.Length == 0 || end > len(msg) {
		return
	}

	c.deliverRX(msg[channelDataHeaderLen:end])
	// Credit AMT for the bytes we accepted so large transfers don't stall.
	if err := c.sendRaw(apf.BuildChannelWindowAdjustBytes(c.amtCh.Load(), hdr.Length)); err != nil {
		log.Tracef("apfconn: window adjust send failed: %v", err)
	}
}

func (c *APFConn) onWindowAdjust(msg []byte) {
	var adj apf.APF_CHANNEL_WINDOW_ADJUST_MESSAGE
	if err := binary.Read(bytes.NewReader(msg), binary.BigEndian, &adj); err != nil {
		return
	}

	c.addTXWindow(adj.BytesToAdd)
}

func (c *APFConn) onKeepAlive(msg []byte) {
	var reply bytes.Buffer
	if err := binary.Write(&reply, binary.BigEndian, apf.ProcessKeepAliveRequest(msg, nil)); err != nil {
		return
	}

	if err := c.sendRaw(reply.Bytes()); err != nil {
		log.Tracef("apfconn: keepalive reply send failed: %v", err)
	}
}

// Read returns received channel-data bytes, blocking until some arrive, the
// channel closes, or the read deadline fires.
func (c *APFConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		c.rxMu.Lock()

		if len(c.rxBuf) > 0 {
			n := copy(p, c.rxBuf)
			c.rxBuf = c.rxBuf[n:]

			if len(c.rxBuf) == 0 {
				c.rxBuf = nil
			}

			c.rxMu.Unlock()

			return n, nil
		}

		err := c.rxErr
		c.rxMu.Unlock()

		if err != nil {
			return 0, err
		}

		select {
		case <-c.rxNotify:
		case <-c.readDeadline.wait():
			return 0, timeoutError{}
		case <-c.closeReq:
			return 0, c.rxErrOrDefault(errChannelClosed)
		}
	}
}

// Write frames p into one or more APF_CHANNEL_DATA messages, respecting AMT's
// transmit window and the HECI message size.
func (c *APFConn) Write(p []byte) (int, error) {
	sent := 0

	for sent < len(p) {
		win, err := c.awaitWindow()
		if err != nil {
			return sent, err
		}

		chunk := len(p) - sent
		if uint32(chunk) > win {
			chunk = int(win)
		}

		if chunk > c.maxChunk {
			chunk = c.maxChunk
		}

		frame := apf.BuildChannelDataBytes(c.amtCh.Load(), p[sent:sent+chunk])
		if err := c.sendRaw(frame); err != nil {
			return sent, err
		}

		c.subTXWindow(uint32(chunk))

		sent += chunk
	}

	return sent, nil
}

// awaitWindow blocks until AMT has granted transmit credit, returning the
// current window. It honors the write deadline and channel close.
func (c *APFConn) awaitWindow() (uint32, error) {
	for {
		c.txMu.Lock()
		win := c.txWindow
		c.txMu.Unlock()

		if win > 0 {
			return win, nil
		}

		select {
		case <-c.txNotify:
		case <-c.writeDeadline.wait():
			return 0, timeoutError{}
		case <-c.closeReq:
			return 0, c.rxErrOrDefault(errChannelClosed)
		}
	}
}

// Close tears down the channel: it stops the read pump, best-effort notifies AMT
// with APF_CHANNEL_CLOSE, and wakes any blocked Read/Write. It does not close the
// HECI handle (the caller owns that).
func (c *APFConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeReq)

		if c.established.Load() {
			_ = c.sendRaw(apf.BuildChannelCloseBytes(c.amtCh.Load()))
		}

		c.rxMu.Lock()

		if c.rxErr == nil {
			c.rxErr = errChannelClosed
		}

		c.rxMu.Unlock()
		c.pokeRX()
		c.pokeTX()
	})

	return nil
}

// Done is closed once the read pump has exited. The owner of the HECI handle can
// wait on it before reusing the handle for another channel.
func (c *APFConn) Done() <-chan struct{} {
	return c.done
}

func (c *APFConn) LocalAddr() net.Addr  { return apfAddr("lme") }
func (c *APFConn) RemoteAddr() net.Addr { return apfAddr(fmt.Sprintf("amt:%d", c.port)) }

func (c *APFConn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t)
	c.writeDeadline.set(t)

	return nil
}

func (c *APFConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)

	return nil
}

func (c *APFConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.set(t)

	return nil
}

// sendRaw writes one fully framed APF message to HECI under writeMu so the pump
// and Write never interleave bytes from two messages.
func (c *APFConn) sendRaw(b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return c.cmd.Send(b)
}

func (c *APFConn) signalOpen(err error) {
	select {
	case c.openCh <- err:
	default:
	}
}

func (c *APFConn) deliverRX(payload []byte) {
	c.rxMu.Lock()
	c.rxBuf = append(c.rxBuf, payload...)
	c.rxMu.Unlock()
	c.pokeRX()
}

func (c *APFConn) failRX(err error) {
	c.rxMu.Lock()

	if c.rxErr == nil {
		c.rxErr = err
	}

	c.rxMu.Unlock()
	c.pokeRX()
}

func (c *APFConn) rxErrOrDefault(def error) error {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()

	if c.rxErr != nil {
		return c.rxErr
	}

	return def
}

func (c *APFConn) pokeRX() {
	select {
	case c.rxNotify <- struct{}{}:
	default:
	}
}

func (c *APFConn) pokeTX() {
	select {
	case c.txNotify <- struct{}{}:
	default:
	}
}

func (c *APFConn) setTXWindow(w uint32) {
	c.txMu.Lock()
	c.txWindow = w
	c.txMu.Unlock()
	c.pokeTX()
}

func (c *APFConn) addTXWindow(delta uint32) {
	c.txMu.Lock()
	c.txWindow += delta
	c.txMu.Unlock()
	c.pokeTX()
}

func (c *APFConn) subTXWindow(delta uint32) {
	c.txMu.Lock()

	if delta >= c.txWindow {
		c.txWindow = 0
	} else {
		c.txWindow -= delta
	}

	c.txMu.Unlock()
}

// apfAddr is a trivial net.Addr for the APF/HECI transport.
type apfAddr string

func (a apfAddr) Network() string { return "apf" }
func (a apfAddr) String() string  { return string(a) }

// timeoutError satisfies net.Error with Timeout() == true so crypto/tls and
// net/http treat a deadline expiry as a timeout rather than a fatal error.
type timeoutError struct{}

func (timeoutError) Error() string   { return "apf: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// connDeadline is a settable deadline whose wait() channel closes when the
// deadline fires. Adapted from the standard library's net.Pipe implementation so
// SetDeadline can interrupt an in-flight Read/Write (which crypto/tls relies on
// to cancel a handshake via context).
type connDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func makeConnDeadline() connDeadline {
	return connDeadline{cancel: make(chan struct{})}
}

func (d *connDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // wait for the timer callback to finish closing cancel
	}

	d.timer = nil

	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}

		return
	}

	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}

		d.timer = time.AfterFunc(dur, func() {
			close(d.cancel)
		})

		return
	}

	if !closed {
		close(d.cancel)
	}
}

func (d *connDeadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
