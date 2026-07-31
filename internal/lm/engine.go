/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package lm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/apf"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/pthi"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// defaultLMEPort is the AMT-side management TCP port (HTTP) that a fresh
// CHANNEL_OPEN targets before any RPS port_switch moves traffic to 16993.
const defaultLMEPort uint32 = 16992

// LMConnection is struct for managing connection to LMS
type LMEConnection struct {
	Command    pthi.Command
	Session    *apf.Session
	ourChannel int
	retries    int
	// port is the AMT-side TCP port that each CHANNEL_OPEN targets. Defaults
	// to 16992 (HTTP); switched to 16993 after RPS port_switch so subsequent
	// wsman traffic rides the TLS-enforced port.
	port uint32

	// tunnel marks the connection as a persistent TLS tunnel. In tunnel mode a
	// single Listen goroutine spans every TLS round of one session, so a benign
	// HECI read timeout (no data this round) must NOT exit the loop the way the
	// one-shot request/response path relies on - otherwise the rounds after the
	// handshake response (the encrypted WSMAN request/response) have no reader.
	tunnel bool
	// stopListen retires the persistent tunnel Listen goroutine when a new TLS
	// session (ClientHello) supersedes the current one, so two Receive loops
	// never race on the same HECI handle. Recreated by EnableTunnel per session.
	stopListen chan struct{}
	stopClosed bool
	stopMu     sync.Mutex
}

// SetPort changes the AMT-side port used for subsequent CHANNEL_OPENs.
func (lme *LMEConnection) SetPort(port uint32) {
	lme.port = port
}

// EnableTunnel wires the APF session's StreamDataBuffer so each incoming
// APF_CHANNEL_DATA chunk is delivered to stream immediately, instead of being
// buffered into Tempdata and only flushed on CHANNEL_CLOSE. Required for
// TLS-tunnel mode: the executor must forward AMT's TLS handshake bytes to
// RPS as they arrive so RPS can produce the next handshake message, rather
// than after AMT gives up and closes the channel.
func (lme *LMEConnection) EnableTunnel(stream chan []byte) {
	if lme.Session != nil {
		lme.Session.StreamDataBuffer = stream
	}

	lme.stopMu.Lock()
	lme.tunnel = true
	lme.stopListen = make(chan struct{})
	lme.stopClosed = false
	lme.stopMu.Unlock()
}

// StopListen signals the current persistent tunnel Listen goroutine to exit at
// its next loop iteration. Safe to call multiple times and before any tunnel
// has been enabled. Used when a new TLS session supersedes the current one so
// the old listener can't keep reading on a channel that's being torn down.
func (lme *LMEConnection) StopListen() {
	lme.stopMu.Lock()
	defer lme.stopMu.Unlock()

	if lme.stopListen != nil && !lme.stopClosed {
		close(lme.stopListen)
		lme.stopClosed = true
	}
}

// AMT advertises tcpip-forward for a management port plus a matching
// redirection port. Which ports appear depends on whether TLS is enforced:
//   - non-TLS device: 16992 (management) + 623 (redirection)
//   - TLS-enforced device: 16993 (management) + 664 (redirection)
//
// A TLS-enforced device never advertises 16992/623, so the handshake must not
// wait for them - doing so blocks until the heci read timeout (~3s, per
// utils.HeciReadTimeout) on every connection to an AMT with TLS enforced on
// local ports.
var (
	apfMgmtPorts  = []uint32{16992, 16993}
	apfRedirPorts = []uint32{623, 664}
)

type apfInitHandler struct {
	apf.DefaultHandler
	seenPorts map[uint32]bool
}

func (h *apfInitHandler) OnGlobalRequest(req apf.GlobalRequest) bool {
	if req.RequestType != "tcpip-forward" {
		return false
	}

	if h.seenPorts == nil {
		h.seenPorts = make(map[uint32]bool, len(apfMgmtPorts)+len(apfRedirPorts))
	}

	h.seenPorts[req.Port] = true

	return false
}

// allExpectedSeen reports readiness once AMT has advertised a complete
// management+redirection pair for the active mode. Requiring a full pair (not
// just any management plus any redirection registration) preserves the original
// guard against racing a trailing registration into the next CHANNEL_OPEN,
// while avoiding mixed pairs when firmware advertises both modes.
func (h *apfInitHandler) allExpectedSeen() bool {
	// Non-TLS mode:      16992 (management) + 623 (redirection)
	// TLS-enforced mode: 16993 (management) + 664 (redirection)
	return (h.seenPorts[apfMgmtPorts[0]] && h.seenPorts[apfRedirPorts[0]]) ||
		(h.seenPorts[apfMgmtPorts[1]] && h.seenPorts[apfRedirPorts[1]])
}

func NewLMEConnection(data chan []byte, errors chan error, wg *sync.WaitGroup) *LMEConnection {
	lme := &LMEConnection{
		ourChannel: 1,
		port:       defaultLMEPort,
	}
	lme.Command = pthi.NewCommand()
	lme.Session = &apf.Session{
		DataBuffer:  data,
		ErrorBuffer: errors,
		Tempdata:    []byte{},
		WaitGroup:   wg,
	}

	return lme
}

// WaitChan returns a channel that is closed once wg's counter reaches zero. It
// lets a caller select on handshake completion alongside error/timeout channels
// without open-coding the bridging goroutine at every channel-open site. The
// spawned goroutine outlives the select when another branch fires first, which
// is intentional: it unblocks as soon as the abandoned WaitGroup is drained.
func WaitChan(wg *sync.WaitGroup) <-chan struct{} {
	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	return done
}

// ResetHandshake installs a fresh WaitGroup on the LME session so each request
// starts from a known-zero counter; a stale Done() from an abandoned Listen can
// no longer race the current attempt's handshake wait. The new WaitGroup is
// returned for callers that want to wait on it directly. When the session has
// not been created yet the WaitGroup is returned without being wired in.
func (lme *LMEConnection) ResetHandshake() *sync.WaitGroup {
	wg := &sync.WaitGroup{}

	if lme.Session != nil {
		lme.Session.WaitGroup = wg
	}

	return wg
}

// Initialize closes and reopens the MEI device, then runs the APF handshake.
// Use this for a cold start where no MEI handle is open yet. When the HECI
// layer has already transparently reopened the device (ErrDeviceReinitialized),
// call runAPFHandshake instead to avoid a redundant close/open connect_client
// round-trip.
func (lme *LMEConnection) Initialize() error {
	lme.Command.Close()

	if err := lme.Command.Open(true); err != nil {
		logLMEError(err)

		return err
	}

	return lme.runAPFHandshake()
}

// runAPFHandshake replays the APF protocol handshake (PROTOCOL_VERSION exchange
// + tcpip-forward registrations) on an already-open MEI device. The firmware
// drops the LME session on every CHANNEL_CLOSE, so this runs once per request;
// keeping it independent of the device open lets the reinit path skip a second
// MEI open that the HECI layer already performed.
func (lme *LMEConnection) runAPFHandshake() error {
	handler := &apfInitHandler{}
	processor := apf.NewProcessor(handler)

	var pv bytes.Buffer
	if err := binary.Write(&pv, binary.BigEndian, apf.ProtocolVersion(1, 0, 9)); err != nil {
		return err
	}

	if err := lme.Command.Send(pv.Bytes()); err != nil {
		logLMEError(err)

		return err
	}

	for {
		result, bytesRead, err := lme.Command.Receive()
		if err != nil {
			if heci.IsReadTimeout(err) {
				// ME went idle; handshake phase is complete.
				return nil
			}

			logLMEError(err)

			return err
		}

		if bytesRead == 0 {
			// No more init messages queued.
			return nil
		}

		reply := processor.Process(result[:bytesRead], lme.Session)
		if reply.Len() > 0 {
			if err := lme.Command.Send(reply.Bytes()); err != nil {
				logLMEError(err)

				return err
			}
		}

		if handler.allExpectedSeen() {
			return nil
		}
	}
}

// ReestablishAPF replays the APF protocol handshake after the HECI layer has
// transparently reopened the MEI device (ErrDeviceReinitialized). The firmware
// drops its LME/APF session on the reopen, so a CHANNEL_OPEN issued before the
// reinit is stale; callers must re-open the channel after this returns. The
// device is already open at this point, so this only drives the handshake (no
// redundant MEI close/open).
func (lme *LMEConnection) ReestablishAPF() error {
	return lme.runAPFHandshake()
}

// Connect initializes connection to LME via MEI Driver
func (lme *LMEConnection) Connect() error {
	log.Debug("Sending APF_CHANNEL_OPEN")

	// Reset per-request session state before a new channel open. Clearing
	lme.Session.RecipientChannel = 0
	// RecipientChannel is critical: a late APF_CHANNEL_CLOSE for the previous
	// channel can arrive after EnableTunnel has swapped in the new stream but
	// before OPEN_CONFIRMATION sets the new RecipientChannel; without this
	// reset the recipient-match guard in ProcessChannelClose would treat the
	// stale close as targeting the new stream and close it.
	lme.Session.Tempdata = []byte{}
	lme.Session.SenderChannel = 0
	lme.Session.TXWindow = 0
	lme.Session.HandshakeConfirmed = false

	var lastErr error

	for attempts := 0; attempts < 4; attempts++ {
		channel := ((lme.ourChannel + 1) % 32)
		if channel == 0 {
			lme.ourChannel = 1
		} else {
			lme.ourChannel = channel
		}

		port := lme.port
		if port == 0 {
			port = defaultLMEPort
		}

		bin_buf := apf.ChannelOpenPort(lme.ourChannel, port)

		// Account for this CHANNEL_OPEN before Send so a concurrent APF listener
		// can't process OPEN_CONFIRMATION/OPEN_FAILURE and call Done() first.
		// This ordering prevents WaitGroup underflow across retry attempts.
		if lme.Session.WaitGroup != nil {
			lme.Session.WaitGroup.Add(1)
		}

		err := lme.Command.Send(bin_buf.Bytes())
		if err != nil {
			// Undo the Add(1) since we failed to send the channel open
			if lme.Session.WaitGroup != nil {
				lme.Session.WaitGroup.Done()
			}

			lastErr = err
			if attempts < 4 && (errors.Is(err, heci.ErrDeviceReinitialized) || err.Error() == "no such device" || err.Error() == "The device is not connected.") {
				log.Warn(err.Error())
				log.Warn("Retrying...")

				// On ErrDeviceReinitialized the HECI layer already reopened
				// and reconnected the MEI device; only the APF session state
				// was lost. Replay just the handshake instead of closing and
				// reopening the device again - that second open costs an extra
				// connect_client round-trip on every request. For the other
				// error strings the device is not known-open, so fall back to
				// a full Initialize (open + handshake).
				var reinitErr error
				if errors.Is(err, heci.ErrDeviceReinitialized) {
					reinitErr = lme.runAPFHandshake()
				} else {
					reinitErr = lme.Initialize()
				}

				if reinitErr != nil {
					return reinitErr
				}

				// On the ErrDeviceReinitialized path runAPFHandshake already
				// blocked until the ME re-advertised all four tcpip-forward
				// bindings (allExpectedSeen), so the device is ready - retry
				// the CHANNEL_OPEN immediately. Only the full-Initialize
				// fallback, which just reopened the device, gets a brief
				// settle before retrying.
				if !errors.Is(err, heci.ErrDeviceReinitialized) {
					time.Sleep(utils.HeciReinitDelay * time.Millisecond)
				}

				continue
			}

			log.Error(err)

			return err
		}

		lme.retries = 0

		return nil
	}

	return lastErr
}

func logLMEError(err error) {
	if err == nil {
		return
	}

	if heci.IsReadTimeout(err) {
		log.Warn(err)

		return
	}

	log.Error(err)
}

// Send writes data to LMS TCP Socket
func (lme *LMEConnection) Send(data []byte) error {
	log.Debugf("sending message to LME, LME payload bytes=%d", len(data))

	// Use the proper APF serialization function instead of manual binary.Write
	channelDataBytes := apf.BuildChannelDataBytes(lme.Session.SenderChannel, data)

	// Debit TX window by payload length, not framed length.
	if sent := uint32(len(data)); sent >= lme.Session.TXWindow {
		lme.Session.TXWindow = 0
	} else {
		lme.Session.TXWindow -= sent
	}

	err := lme.Command.Send(channelDataBytes)
	if err != nil {
		return err
	}

	log.Debug("sent message to LME")

	return nil
}

// Listen dispatches APF messages. In one-shot (non-tunnel) mode it returns
// after a single transaction (CHANNEL_CLOSE, OPEN_FAILURE, or a read timeout).
// In tunnel mode it stays alive across every TLS round of the session: a benign
// read timeout (no data this round) just loops, so the rounds after the
// handshake response (the encrypted WSMAN request/response) still have a reader.
// It exits on a real error, on CHANNEL_CLOSE for the confirmed channel, or when
// StopListen is signaled for a superseding session.
func (lme *LMEConnection) Listen() {
	lme.stopMu.Lock()
	tunnel := lme.tunnel
	stop := lme.stopListen
	lme.stopMu.Unlock()

	for {
		if tunnel && stop != nil {
			select {
			case <-stop:
				log.Trace("LME tunnel listener stopped for superseding session")

				return
			default:
			}
		}

		result, bytesRead, err := lme.Command.Receive()
		if bytesRead == 0 || err != nil {
			// In tunnel mode a benign read timeout means AMT simply had nothing
			// to send this round (e.g. right after the client Finished, before
			// the encrypted request arrives). Keep the single persistent
			// listener alive across rounds instead of exiting; the one-shot
			// path still exits so its caller's WaitGroup/error flow is intact.
			if tunnel && (err == nil || heci.IsReadTimeout(err)) {
				continue
			}

			log.Trace("NO MORE DATA TO READ")

			// Non-blocking send so a closed error channel doesn't leak the goroutine.
			if err != nil {
				select {
				case lme.Session.ErrorBuffer <- err:
				default:
					log.Debug("Error channel closed, exiting Listen")
				}
			}

			return
		}

		msg := result[:bytesRead]
		msgType := msg[0]

		reply := apf.Process(msg, lme.Session)
		if reply.Len() > 0 {
			if err := lme.Command.Send(reply.Bytes()); err != nil {
				log.Trace(err)

				return
			}
		}

		// One transaction per Listen; Process already handed off body/error.
		if msgType == apf.APF_CHANNEL_OPEN_FAILURE {
			return
		}

		// HandshakeConfirmed guards against stale CLOSE frames from a previous
		// channel (reset by Connect). Additionally require the CLOSE to target
		// our active channel: AMT replays stale CHANNEL_CLOSE frames for old
		// channels (e.g. RecipientChannel 0 after an MEI reinit) while the
		// current channel is still live and about to deliver its response.
		// Exiting on those drops the real response and forces a needless
		// re-handshake, so only a CLOSE for our channel ends the listener.
		if msgType == apf.APF_CHANNEL_CLOSE && lme.Session.HandshakeConfirmed &&
			closeTargetsOurChannel(msg, lme.Session) {
			return
		}
	}
}

// closeTargetsOurChannel reports whether an APF_CHANNEL_CLOSE frame refers to
// the session's currently confirmed channel. AMT addresses the close by our
// (recipient) channel number, which Process records as Session.RecipientChannel
// on OPEN_CONFIRMATION. A mismatch means the close is for a superseded channel
// (commonly RecipientChannel 0 after an MEI reinit) and must not tear down the
// active listener before AMT delivers the pending response.
func closeTargetsOurChannel(msg []byte, session *apf.Session) bool {
	const channelCloseHeaderLen = 5 // MessageType(1) + RecipientChannel(4)
	if len(msg) < channelCloseHeaderLen {
		return false
	}

	return binary.BigEndian.Uint32(msg[1:channelCloseHeaderLen]) == session.RecipientChannel
}

// Close closes the LME connection
func (lme *LMEConnection) Close() error {
	log.Debug("closing connection to lme")
	lme.Command.Close()

	return nil
}
