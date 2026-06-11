/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/apf"
	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// handshakeTimeout bounds the wait for APF_CHANNEL_OPEN_CONFIRMATION so a Listen
// goroutine that exits before signaling Done() can't deadlock the activation loop.
// Derived from utils.LMEChannelOpenTimeout so executor and localTransport share a
// single source of truth for the value.
var handshakeTimeout = utils.LMEChannelOpenTimeout * time.Second

// maxPortSwitchDelaySeconds caps the AMT TLS-restart wait that RPS asks for via
// the port_switch payload. The server-supplied value is clamped to this maximum
// to bound how long the activation loop can be blocked on a (possibly hostile
// or buggy) server-controlled delay. Overridable via RPC_PORT_SWITCH_MAX_DELAY.
var maxPortSwitchDelaySeconds = envInt("RPC_PORT_SWITCH_MAX_DELAY", 60)

// extraPortSwitchDelaySeconds is added on top of the server-requested delay
// (after clamping). Useful when AMT's TLS subsystem needs more time than RPS
// expects to bind the freshly-committed server cert to port 16993; raise this
// if you see "Failed to establish TLS tunnel connection" errors immediately
// after port_switch. Overridable via RPC_PORT_SWITCH_EXTRA_DELAY.
var extraPortSwitchDelaySeconds = envInt("RPC_PORT_SWITCH_EXTRA_DELAY", 0)

// envInt returns the integer value of env var name, or def if unset/invalid.
func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		log.Warnf("ignoring invalid %s=%q: %v", name, v, err)

		return def
	}

	if n < 0 {
		log.Warnf("ignoring negative %s=%q", name, v)

		return def
	}

	return n
}

// waitWithSignal sleeps for d but returns early with an error if SIGINT/SIGTERM
// arrives, so the activation loop can abort promptly on Ctrl+C rather than
// being held by a server-requested delay.
func waitWithSignal(d time.Duration) error {
	sigCh := make(chan os.Signal, 1)

	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	timer := time.NewTimer(d)

	select {
	case <-timer.C:
		return nil
	case sig := <-sigCh:
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		return fmt.Errorf("port-switch wait interrupted by %v", sig)
	}
}

type Executor struct {
	server          AMTActivationServer
	localManagement lm.LocalMananger
	isLME           bool
	payload         Payload
	data            chan []byte
	errors          chan error
	waitGroup       *sync.WaitGroup
	lastError       error
	// TLS tunnel state
	tlsTunnelActive bool // true after port switch; gates tunnel behaviors
	lmConnected     bool // tracks if LMS connection is active (for TLS tunnel persistence)

	// lmeStream carries individual APF_CHANNEL_DATA chunks from the AMT side
	// during LME TLS-tunnel mode; lmeStreamForwarder forwards them into e.data,
	// and HandleDataFromRPS coalesces chunks per RPS round-trip before
	// forwarding to RPS. nil outside LME tunnel mode.
	lmeStream chan []byte

	// lmeListenDone is closed when the current persistent LME tunnel Listen
	// goroutine exits. stopLMEListen waits on it before opening a new session
	// so two Receive loops never race on the same HECI handle. nil when no
	// tunnel listener has been started.
	lmeListenDone chan struct{}

	// lmeForwarderStop/lmeForwarderDone control the APF stream forwarder
	// goroutine lifecycle so a superseded session cannot leave a stale forwarder
	// blocked forever on a stream channel that never closes.
	lmeForwarderStop chan struct{}
	lmeForwarderDone chan struct{}
}
type ExecutorConfig struct {
	URL              string
	Proxy            string
	LocalTlsEnforced bool
	SkipAmtCertCheck bool
	ControlMode      int
	SkipCertCheck    bool
	TLSTunnel        bool
}

func NewExecutor(config ExecutorConfig) (Executor, error) {
	// these are closed in the close function for each lm implementation
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	port := utils.LMSPort
	if config.LocalTlsEnforced {
		port = utils.LMSTLSPort
	}

	client := Executor{
		server:          NewAMTActivationServer(config.URL, config.Proxy),
		localManagement: lm.NewLMSConnection(utils.LMSAddress, port, config.LocalTlsEnforced, lmDataChannel, lmErrorChannel, config.ControlMode, config.SkipAmtCertCheck),
		data:            lmDataChannel,
		errors:          lmErrorChannel,
		waitGroup:       &sync.WaitGroup{},
		tlsTunnelActive: config.LocalTlsEnforced,
	}

	// TEST CONNECTION TO SEE IF LMS EXISTS
	err := client.localManagement.Connect()
	if err != nil {
		log.Tracef("LMS dial failed (%v); falling back to LME (in-band HECI/APF)", err)

		lme := lm.NewLMEConnection(lmDataChannel, lmErrorChannel, client.waitGroup)
		// On TLS-enforced AMT the active local port is 16993; aim the first
		// CHANNEL_OPEN there so RPS doesn't have to issue a port_switch just
		// to get past the activation handshake.
		if config.LocalTlsEnforced {
			lme.SetPort(16993)
		}

		client.localManagement = lme
		client.isLME = true
		if err := client.localManagement.Initialize(); err != nil {
			return Executor{}, fmt.Errorf("failed to initialize LME connection: %w", err)
		}
	} else {
		log.Trace("Using existing LMS\n")
		client.localManagement.Close()
	}

	err = client.server.Connect(config.SkipCertCheck)
	if err != nil {
		// TODO: should the connection be closed?
		// client.localManagement.Close()
		log.Error("error connecting to RPS")
	}

	return client, err
}

// MakeItSo uses a pointer receiver because it updates executor state (lastError)
// across the activation loop.
func (e *Executor) MakeItSo(messageRequest Message) error {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	rpsDataChannel := e.server.Listen()

	log.Debug("sending activation request to RPS")

	err := e.server.Send(messageRequest)
	if err != nil {
		log.Error(err.Error())

		return fmt.Errorf("failed to send activation request: %w", err)
	}

	defer e.localManagement.Close()

	for {
		select {
		case dataFromServer, ok := <-rpsDataChannel:
			if !ok {
				e.lastError = errors.New("rps connection closed unexpectedly")

				return e.lastError
			}

			shallIReturn := e.HandleDataFromRPS(dataFromServer)
			if shallIReturn { // quits the loop -- we're either done or reached a point where we need to stop
				return e.lastError
			}
		case <-interrupt:
			e.HandleInterrupt()

			return fmt.Errorf("interrupted by user")
		}
	}
}

func (e Executor) HandleInterrupt() {
	log.Info("interrupt")

	// Cleanly close the connection by sending a close message and then
	// waiting (with timeout) for the server to close the connection.
	// err := e.localManagement.Close()
	// if err != nil {
	// 	log.Error("Connection close failed", err)
	// 	return
	// }
	err := e.server.Close()
	if err != nil {
		log.Error("Connection close failed", err)

		return
	}
}

// HandleDataFromRPS processes one RPS message and returns true when activation should stop.
func (e *Executor) HandleDataFromRPS(dataFromServer []byte) bool {
	msg, err := e.server.ProcessMessage(dataFromServer)
	if err != nil {
		e.lastError = err

		return true
	}

	if msg.Terminal {
		log.Info("RPS sent terminal message (success/error), ending activation flow")

		return true
	}

	switch msg.Method {
	case "heartbeat":
		return false
	case MethodPortSwitch:
		if err := e.handlePortSwitch(string(msg.Payload)); err != nil {
			log.Error("Port switch failed: ", err)
			e.lastError = fmt.Errorf("port switch failed: %w", err)

			return true
		}

		return false
	}

	// Detect TLS ClientHello - close existing connection so firmware can renegotiate.
	// In LME mode the per-TLS-session resource is just the APF channel (already
	// torn down by AMT on the previous CHANNEL_CLOSE, which cleared lmConnected
	// via lmeStreamForwarder); the HECI handle owns the tcpip-forward port
	// registrations from Initialize() and must stay open across TLS sessions.
	if len(msg.Payload) >= 6 && msg.Payload[0] == 0x16 && msg.Payload[5] == 0x01 && e.lmConnected {
		log.Debug("TLS ClientHello detected, closing existing connection for new handshake")

		if !e.isLME {
			e.localManagement.Close()
		}

		e.lmConnected = false
	}

	log.Debug("RPS sent activation data, processing...")

	// Set up connection and listener based on transport mode
	if e.isLME {
		if e.tlsTunnelActive {
			if err := e.prepareLMETunnel(); err != nil {
				e.lastError = err

				return true
			}
		} else {
			if err := e.prepareLME(); err != nil {
				e.lastError = err

				return true
			}
		}
	} else if e.tlsTunnelActive {
		if err := e.prepareLMSTunnel(); err != nil {
			e.lastError = err

			return true
		}
	} else {
		if err := e.prepareLMS(); err != nil {
			e.lastError = err

			return true
		}

		defer func() {
			e.localManagement.Close()
			e.lmConnected = false
		}()
	}

	// Unified send across all transport modes
	err = e.localManagement.Send(msg.Payload)
	if err != nil {
		e.lastError = fmt.Errorf("failed to send payload to LME/LMS: %w", err)
		log.Error(err)

		return true
	}

	// Use longer timeout for TLS tunnel mode (AMT may take 60+ seconds for TLS restart)
	responseTimeout := utils.AMTResponseTimeout * time.Second
	if e.tlsTunnelActive {
		responseTimeout = utils.TLSTunnelResponseTimeout * time.Second
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), responseTimeout)
	defer cancel()

	// In LME TLS-tunnel mode, bound the wait for AMT's first response byte on
	// EVERY round, mirroring the LMS reference path (lm.LMSConnection.Listen,
	// which uses a flat 2s first-byte read timeout regardless of TLS record
	// type). A TLS handshake has rounds that legitimately produce zero AMT-side
	// bytes, and the record type does NOT reliably identify them: under TLS 1.2
	// the silent round is the client's ChangeCipherSpec+Finished (0x14), but
	// under TLS 1.3 it is the encrypted client Finished, which travels as an
	// application-data record (0x17) - indistinguishable by first byte from a
	// WSMAN request. Conversely a HelloRetryRequest round opens with a 0x14 CCS
	// yet still expects the server's certificate flight. Gating on the record
	// type therefore both misses the TLS 1.3 Finished (hanging the full response
	// timeout) and risks yielding on a HRR round. AMT's real responses arrive
	// well within this window, so a flat first-byte timeout yields promptly on
	// the genuinely-silent round while still forwarding every real reply. The
	// persistent Listen goroutine stays alive across the yield, so a slightly
	// late response is not lost.
	var firstByteC <-chan time.Time

	if e.isLME && e.tlsTunnelActive {
		firstByteTimer := time.NewTimer(lmeTunnelFirstByteTimeout)
		defer firstByteTimer.Stop()

		firstByteC = firstByteTimer.C
	}

	// In LME TLS-tunnel mode also watch the persistent listener's done channel.
	// AMT ends a TLS session by closing the APF channel, but it sometimes sends
	// the CHANNEL_CLOSE with RecipientChannel 0, which the APF layer can't key to
	// our channel, so no stream-close sentinel reaches the receive path. The
	// listener itself always exits on CHANNEL_CLOSE though; observing that exit
	// here lets us re-handshake immediately instead of blocking until the
	// response timeout.
	var listenDoneC <-chan struct{}

	if e.isLME && e.tlsTunnelActive {
		listenDoneC = e.lmeListenDone
	}

	for {
		select {
		case dataFromLM := <-e.data:
			if len(dataFromLM) == 0 {
				if e.tlsTunnelActive {
					log.Warn("Empty response from LMS - sending connection_reset")

					// LME tunnel mode: don't close the HECI handle (it owns the
					// tcpip-forward registrations); just mark the per-channel
					// state stale so the next prepareLMETunnel opens a fresh
					// APF channel for the new TLS session.
					if !e.isLME {
						e.localManagement.Close()
					}

					e.lmConnected = false

					resetMsg := e.payload.CreateMessageResponse([]byte("connection_closed"), MethodConnectionReset)
					e.server.Send(resetMsg)
				}

				return false
			}

			// In LME TLS-tunnel mode a single TLS round-trip arrives as multiple
			// APF_CHANNEL_DATA chunks (e.g. ServerHello, Certificate, SKE, …).
			// RPS's TLS-tunnel manager treats each tls_data message as a discrete
			// unit, so forwarding each chunk separately hands it fragmented TLS
			// records and the handshake fails ("Failed to initialize TLS tunnel").
			// The LMS path (lm.LMSConnection.Listen) coalesces all bytes received
			// within an idle window into one message; mirror that here by draining
			// additional chunks and concatenating them before a single forward.
			if e.isLME && e.tlsTunnelActive {
				coalesced, channelClosed := e.coalesceLMETunnelResponse(dataFromLM)

				log.Debugf("Received response from LME (coalesced %d bytes), forwarding to RPS", len(coalesced))
				e.HandleDataFromLM(coalesced)
				log.Debug("Response sent to RPS, waiting for next RPS message")

				if channelClosed {
					log.Debug("LME tunnel: APF channel closed by AMT mid-session; asking RPS to re-handshake")

					e.lmConnected = false

					resetMsg := e.payload.CreateMessageResponse([]byte("connection_closed"), MethodConnectionReset)
					e.server.Send(resetMsg)

					return false
				}
			} else {
				log.Debug("Received response from LME/LMS, forwarding to RPS")
				e.HandleDataFromLM(dataFromLM)
				log.Debug("Response sent to RPS, waiting for next RPS message")
			}

			if e.isLME && !e.tlsTunnelActive {
				e.waitGroup.Wait()
			}

			// LME holds a persistent HECI handle whose tcpip-forward registrations
			// are established once in Initialize(); closing it between requests
			// invalidates the device for the next RPS message. MakeItSo's deferred
			// Close() handles end-of-flow teardown for LME.
			if !e.tlsTunnelActive && !e.isLME {
				e.localManagement.Close()
				e.lmConnected = false
			}

			return false
		case errFromLMS := <-e.errors:
			if errFromLMS != nil {
				// HECI read timeout is expected while polling for data.
				if errors.Is(errFromLMS, heci.ErrReadTimeout) {
					log.Debug("heci read timeout (normal driver timeout, not an error)")

					continue
				}

				// TLS 1.3 has normal handshake rounds where LMS emits no immediate
				// bytes (e.g. immediately after our client Finished). The LMS
				// Listen goroutine surfaces those via ErrLMSReadTimeoutNoData; in
				// TLS-tunnel mode treat them as a benign continuation so the
				// connection and AMT-side TLS state stay alive and the next
				// queued tls_data RPS message rides the same socket. Outside
				// TLS-tunnel mode the historical fatal handling still applies.
				if e.tlsTunnelActive && errors.Is(errFromLMS, lm.ErrLMSReadTimeoutNoData) {
					log.Trace("No LMS data before read timeout for this TLS round-trip; continuing without connection_reset")

					return false
				}

				log.Error("LMS error: ", errFromLMS)

				if e.tlsTunnelActive {
					if !e.isLME {
						e.localManagement.Close()
					}

					e.lmConnected = false

					resetMsg := e.payload.CreateMessageResponse([]byte("lms_error"), MethodConnectionReset)
					e.server.Send(resetMsg)

					return false
				}

				e.lastError = fmt.Errorf("LME/LMS error: %w", errFromLMS)

				return true
			}
		case <-firstByteC:
			// No first response byte from AMT within the first-byte window for
			// this LME TLS-tunnel round. AMT's real responses arrive well inside
			// this window, so silence here means this is an idle handshake round
			// (e.g. after RPS's client Finished). Yield to RPS keeping the
			// persistent APF channel and Listen goroutine alive so the next
			// pipelined tls_data message rides the same TLS session, mirroring
			// the LMS ErrLMSReadTimeoutNoData behavior.
			log.Trace("No LME tunnel data within first-byte window; yielding to RPS")

			return false
		case <-listenDoneC:
			// The persistent tunnel listener exited: AMT closed the APF channel
			// (and thus this TLS session). When the close carries RecipientChannel
			// 0 the APF layer can't match it to our channel, so no stream-close
			// sentinel is produced and the plain read wait would block until the
			// response timeout. Flush any final bytes the listener forwarded
			// before exiting, hand them to RPS, then ask RPS to re-handshake.
			if final := e.drainLMETunnelData(); len(final) > 0 {
				log.Debugf("Received final response from LME (%d bytes) before channel close, forwarding to RPS", len(final))
				e.HandleDataFromLM(final)
			}

			log.Debug("LME tunnel: listener exited (AMT closed channel); asking RPS to re-handshake")

			e.lmConnected = false

			resetMsg := e.payload.CreateMessageResponse([]byte("connection_closed"), MethodConnectionReset)
			e.server.Send(resetMsg)

			return false
		case <-timeoutCtx.Done():
			// Timeout waiting for response from AMT/LME
			// This indicates AMT is not responding - treat as an error
			log.Error("Timeout waiting for LME response - AMT not responding")

			e.lastError = fmt.Errorf("timeout waiting for AMT response after %v", responseTimeout)

			return true
		}
	}
}

// prepareLME opens a fresh APF channel and waits (with bounded timeout) for
// AMT's CHANNEL_OPEN_CONFIRMATION before sending request data. AMT closes the
// channel after each response, so each request needs its own channel/Listen.
func (e *Executor) prepareLME() error {
	log.Debug("LME: Opening new APF channel for this request")

	var lastErr error

	for attempt := 0; attempt < lmeChannelOpenAttempts; attempt++ {
		// Fresh handshake WaitGroup per attempt: if a prior Listen exited
		// without signaling Done(), the old WG is abandoned rather than
		// deadlocking this one.
		handshake := e.resetHandshake()

		err := e.localManagement.Connect()
		if err != nil {
			return fmt.Errorf("failed to open LME channel: %w", err)
		}

		go e.localManagement.Listen()

		// Bounded wait so a Listen goroutine that exits early on a HECI error
		// can't block this loop forever. OPEN_FAILURE also signals Done().
		handshakeDone := lm.WaitChan(handshake)

		select {
		case <-handshakeDone:
			log.Trace("Channel open confirmation received")

			return nil
		case errFromLMS := <-e.errors:
			if errFromLMS == nil {
				return nil
			}

			// Older AMT firmware (notably AMT16) tears down its tcpip-forward
			// bindings when idle between WSMAN requests and re-advertises them
			// on the next request. A CHANNEL_OPEN that races that teardown is
			// rejected with APF_CHANNEL_OPEN_FAILURE (reason code 1) even though
			// the forward is restored microseconds later - the re-advertising
			// tcpip-forward requests arrive before the failure itself. Retry the
			// open; the Listen goroutine has already exited on the failure, so a
			// fresh Connect+Listen races nothing, and by now the port is bound.
			if errors.Is(errFromLMS, apf.ErrChannelOpenFailure) && attempt < lmeChannelOpenAttempts-1 {
				lastErr = errFromLMS

				log.Debugf("APF channel open rejected (%v); retrying", errFromLMS)
				time.Sleep(lmeChannelOpenRetryDelay)

				continue
			}

			return fmt.Errorf("LME error during channel open: %w", errFromLMS)
		case <-time.After(handshakeTimeout):
			return fmt.Errorf("timed out waiting for APF channel open after %s", handshakeTimeout)
		}
	}

	return fmt.Errorf("LME error during channel open: %w", lastErr)
}

// lmeChannelOpenAttempts bounds how many times prepareLME re-issues an
// APF_CHANNEL_OPEN after AMT rejects it with APF_CHANNEL_OPEN_FAILURE. Older
// firmware drops and re-advertises its tcpip-forward bindings between idle
// requests, so the first open of a request can race the teardown; a couple of
// retries lets the now-rebound port accept the channel.
const lmeChannelOpenAttempts = 3

// lmeChannelOpenRetryDelay is the brief settle wait between channel-open retries
// in prepareLME, giving AMT time to finish re-advertising the tcpip-forward
// bindings before the next CHANNEL_OPEN.
const lmeChannelOpenRetryDelay = 250 * time.Millisecond

// resetHandshake installs a fresh WaitGroup on the LME session so each request
// starts from a known-zero counter; a stale Done() from an abandoned Listen
// can no longer race the current attempt's handshake wait.
func (e *Executor) resetHandshake() *sync.WaitGroup {
	wg := &sync.WaitGroup{}

	if lmec, ok := e.localManagement.(*lm.LMEConnection); ok {
		wg = lmec.ResetHandshake()
	}

	e.waitGroup = wg

	return wg
}

// lmeTunnelIdleWindow is how long the LME tunnel receive loop waits for more
// APF_CHANNEL_DATA chunks after one arrives, before returning to wait for the
// next RPS message. Long enough to coalesce TLS handshake fragments, short
// enough not to add noticeable latency to each round-trip.
const (
	lmeTunnelIdleWindow = 200 * time.Millisecond

	// lmeTunnelCloseWait is how long the LME tunnel receive loop keeps waiting,
	// after AMT's response data has stopped arriving, specifically for the trailing
	// APF_CHANNEL_CLOSE that AMT sends after each HTTP/WSMAN response in
	// TLS-enforced mode (Connection: close — every WSMAN call gets its own channel
	// and TLS session). Catching that close in the same round lets us tell RPS to
	// re-handshake immediately; if we miss it (it arrives after we have already
	// yielded back to RPS) the close sentinel sits unconsumed and RPS stalls until
	// its own multi-second timeout before re-handshaking. AMT emits the close
	// within a few hundred ms of the response, so this returns early in practice;
	// the cap only applies on the rare round where AMT keeps the channel open.
	lmeTunnelCloseWait = 1500 * time.Millisecond
)

// lmeTunnelFirstByteTimeout bounds how long the LME tunnel receive loop waits
// for the FIRST byte of AMT's response to a forwarded tls_data message before
// yielding back to RPS. It is the LME analog of the LMS first-byte read
// timeout (lm.LMSConnection.Listen): in a TLS 1.3 handshake some rounds are
// legitimately silent on AMT's side (e.g. right after RPS's client Finished,
// AMT stays quiet until it receives the encrypted application request), and
// RPS pipelines the next message rather than waiting for a reply. Without this
// bound the loop blocks on the HECI read timeout (HeciReadTimeout, ~3s), which
// exceeds RPS's TLS-operation timeout (~12s → GatewayTimeoutError) and lets the
// persistent Listen goroutine exit, stranding the session.
//
// 3s is hardware-validated (AMT16-21, LME) and must not be lowered blindly: a
// shorter window clips legitimate replies whose first byte lands close to the
// boundary, and yielding early lets AMT's real response interleave with RPS's
// pipelined next message, desynchronizing the tunneled TLS stream and failing
// activation ("Unknown error has occurred / TLSConfiguration Configured"). Kept
// above AMT's near-1s real first-byte latency and below RPS's TLS-op timeout.
// The persistent Listen keeps running across this yield, so a slightly-late
// real response is still read on the next round. Overridable via
// RPC_LME_FIRST_BYTE_MS for hardware that needs a different margin.
var lmeTunnelFirstByteTimeout = time.Duration(envInt("RPC_LME_FIRST_BYTE_MS", 3000)) * time.Millisecond

// lmeListenStopTimeout bounds how long stopLMEListen waits for the previous
// session's persistent Listen goroutine to exit after StopListen is signaled.
// The listener re-checks the stop signal once per HECI read cycle
// (HeciReadTimeout), so a couple of cycles is ample; we cap it low so a
// listener that is wedged in a blocked Receive can't add the full handshake
// timeout of latency to every TLS re-handshake (AMT19 opens a fresh channel,
// and thus a fresh session, for every WSMAN call).
var lmeListenStopTimeout = (utils.HeciReadTimeout + 1) * time.Second

// lmeTunnelStreamBuffer sizes the per-channel stream queue between the APF
// processor and the executor forwarder. AMT chunks ServerHello+Certificate
// into ~5-10 frames; 32 is plenty of headroom for one round-trip.
const lmeTunnelStreamBuffer = 32

// lmeTunnelOpenAttempts bounds how many times prepareLMETunnel re-opens the APF
// channel when the MEI link drops mid-open. AMT tears the connection down after
// a channel close, so the first re-open after a re-handshake can race a HECI
// reinit that loses the CHANNEL_OPEN; replaying the handshake and retrying
// recovers it. A couple of retries is ample - the reinit settles immediately.
const lmeTunnelOpenAttempts = 3

// drainLMEChunks collects APF_CHANNEL_DATA chunks belonging to one TLS round
// from e.data into a single payload, starting from initial. It resets an idle
// timer (window idle) on every chunk and returns once the queue stays idle for
// a full window or the forwarder's zero-length channel-closed sentinel arrives
// (sawSentinel true). When closeWait is non-zero the idle timeout is extended
// once to closeWait - specifically to catch AMT's trailing APF_CHANNEL_CLOSE -
// before returning; pass closeWait == 0 to return on the first idle timeout.
func (e *Executor) drainLMEChunks(initial []byte, idle, closeWait time.Duration) (coalesced []byte, sawSentinel bool) {
	coalesced = initial
	window := idle
	timer := time.NewTimer(window)

	defer timer.Stop()

	for {
		select {
		case more := <-e.data:
			if !timer.Stop() {
				<-timer.C
			}

			if len(more) == 0 {
				// Forwarder sentinel: AMT closed the APF channel.
				return coalesced, true
			}

			coalesced = append(coalesced, more...)
			window = idle
			timer.Reset(window)
		case <-timer.C:
			if closeWait == 0 || window == closeWait {
				// No close-wait extension requested, or it already elapsed.
				return coalesced, false
			}

			// Response data has stopped; extend the wait once, specifically to
			// catch AMT's trailing channel close so RPS can re-handshake
			// immediately instead of stalling until its own timeout.
			window = closeWait
			timer.Reset(window)
		}
	}
}

// coalesceLMETunnelResponse drains all APF_CHANNEL_DATA chunks belonging to one
// TLS round (the first chunk is passed in) and then waits briefly for the
// trailing APF_CHANNEL_CLOSE that AMT sends after each HTTP/WSMAN response in
// TLS-enforced mode. RPS's TLS-tunnel manager treats each tls_data message as a
// discrete unit, so all chunks of a round must be concatenated into a single
// forward (mirroring lm.LMSConnection.Listen). It returns the coalesced payload
// and whether AMT closed the channel.
func (e *Executor) coalesceLMETunnelResponse(first []byte) (coalesced []byte, channelClosed bool) {
	return e.drainLMEChunks(first, lmeTunnelIdleWindow, lmeTunnelCloseWait)
}

// drainLMETunnelData collects any APF_CHANNEL_DATA chunks the tunnel forwarder
// has already queued into e.data (e.g. AMT's final response that arrived just
// before it closed the channel) without blocking on new AMT traffic. It is used
// when the persistent listener has exited (AMT closed the channel) to flush a
// trailing response to RPS before asking it to re-handshake. It returns once the
// queue stays idle for one lmeTunnelIdleWindow or the forwarder's zero-length
// channel-closed sentinel arrives.
func (e *Executor) drainLMETunnelData() []byte {
	coalesced, _ := e.drainLMEChunks(nil, lmeTunnelIdleWindow, 0)

	return coalesced
}

// prepareLMSTunnel ensures the persistent tunnel connection is ready and starts a listener.
func (e *Executor) prepareLMSTunnel() error {
	if !e.lmConnected {
		err := e.localManagement.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect to LMS: %w", err)
		}

		e.lmConnected = true
	}

	go e.localManagement.Listen()

	return nil
}

// prepareLMS opens a fresh LMS connection and starts a listener (non-tunnel mode).
func (e *Executor) prepareLMS() error {
	err := e.localManagement.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to LMS: %w", err)
	}

	go e.localManagement.Listen()

	return nil
}

// prepareLMETunnel opens the LME APF channel ONCE, wires the apf session's
// StreamDataBuffer so CHANNEL_DATA chunks stream out as they arrive (instead
// of being buffered until CHANNEL_CLOSE), and starts a single persistent
// Listen goroutine plus a forwarder that pipes the stream into e.data. The
// same channel is reused for every subsequent RPS tls_data write so the TLS
// session stays alive across handshake messages.
func (e *Executor) prepareLMETunnel() error {
	if e.lmConnected {
		return nil
	}

	lmec, ok := e.localManagement.(*lm.LMEConnection)
	if !ok {
		return fmt.Errorf("LME tunnel requires *lm.LMEConnection")
	}

	// Retire any previous session's persistent listener before opening a new
	// channel so we never run two Receive loops on the same HECI handle.
	e.stopLMEListen(lmec)

	// Drain any leftover bytes or sentinels left in e.data by the previous
	// session's forwarder so the next receive loop doesn't treat them as part
	// of the new TLS handshake response.
drain:
	for {
		select {
		case <-e.data:
		default:
			break drain
		}
	}

	e.lmeStream = make(chan []byte, lmeTunnelStreamBuffer)
	lmec.EnableTunnel(e.lmeStream)

	log.Debug("LME tunnel: opening persistent APF channel for TLS session")

	for attempt := 0; attempt < lmeTunnelOpenAttempts; attempt++ {
		handshake := e.resetHandshake()

		if err := lmec.Connect(); err != nil {
			return fmt.Errorf("failed to open LME channel: %w", err)
		}

		// The tunnel Listen goroutine is persistent: it spans every TLS round of
		// this session. lmeListenDone lets stopLMEListen join it before the next
		// session opens.
		listenDone := make(chan struct{})
		e.lmeListenDone = listenDone

		go func() {
			lmec.Listen()
			close(listenDone)
		}()

		handshakeDone := lm.WaitChan(handshake)

		confirmed := false

		select {
		case <-handshakeDone:
			confirmed = true
		case errFromLMS := <-e.errors:
			if errors.Is(errFromLMS, heci.ErrDeviceReinitialized) {
				// AMT tore the MEI link down after the previous channel close;
				// the HECI layer transparently reopened it, so the firmware
				// replayed its APF init and the CHANNEL_OPEN we just sent was
				// lost. Wait for the listener to exit, complete the replayed
				// handshake, then retry the channel open on the fresh session.
				<-listenDone

				e.lmeListenDone = nil

				log.Debug("LME tunnel: MEI reinitialized during channel open; replaying APF handshake and retrying")

				if err := lmec.ReestablishAPF(); err != nil {
					return fmt.Errorf("failed to re-establish APF after reinit: %w", err)
				}

				continue
			}

			if errFromLMS != nil {
				return fmt.Errorf("LME error during channel open: %w", errFromLMS)
			}

			// A nil error signals the channel is up (legacy behavior).
			confirmed = true
		case <-time.After(handshakeTimeout):
			return fmt.Errorf("timed out waiting for LME tunnel APF channel open after %s", handshakeTimeout)
		}

		if confirmed {
			log.Trace("LME tunnel: CHANNEL_OPEN_CONFIRMATION received")

			e.lmConnected = true
			forwarderStop := make(chan struct{})
			forwarderDone := make(chan struct{})
			e.lmeForwarderStop = forwarderStop
			e.lmeForwarderDone = forwarderDone

			go e.lmeStreamForwarder(e.lmeStream, forwarderStop, forwarderDone)

			return nil
		}
	}

	return fmt.Errorf("LME tunnel: APF channel open failed after %d attempts", lmeTunnelOpenAttempts)
}

// stopLMEListen retires the persistent tunnel Listen goroutine from a previous
// TLS session and waits for it to exit, so a new session never races a second
// Receive loop against it on the same HECI handle. No-op when no listener is
// tracked (first session) or it has already exited.
func (e *Executor) stopLMEListen(lmec *lm.LMEConnection) {
	e.stopLMEForwarder()

	if e.lmeListenDone == nil {
		return
	}

	lmec.StopListen()

	select {
	case <-e.lmeListenDone:
	case <-time.After(lmeListenStopTimeout):
		log.Warn("LME tunnel: timed out waiting for previous listener to exit")
	}

	e.lmeListenDone = nil
}

func (e *Executor) stopLMEForwarder() {
	if e.lmeForwarderStop == nil || e.lmeForwarderDone == nil {
		return
	}

	close(e.lmeForwarderStop)

	select {
	case <-e.lmeForwarderDone:
	case <-time.After(lmeListenStopTimeout):
		log.Warn("LME tunnel: timed out waiting for previous stream forwarder to exit")
	}

	e.lmeForwarderStop = nil
	e.lmeForwarderDone = nil
}

// lmeStreamForwarder pipes streaming CHANNEL_DATA chunks into the existing
// e.data channel so the receive loop in HandleDataFromRPS picks them up the
// same way it picks up LMS reads. Exits when the stream channel is closed
// (apf processor closes it on CHANNEL_CLOSE for the active channel). On exit
// it pushes a zero-length sentinel into e.data so the receive loop knows the
// AMT-side TLS session is gone and must trigger a connection_reset to RPS.
func (e *Executor) lmeStreamForwarder(stream <-chan []byte, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)

	for {
		select {
		case <-stop:
			log.Debug("LME tunnel: stream forwarder stopped for superseding session")

			return
		case chunk, ok := <-stream:
			if !ok {
				log.Debug("LME tunnel: stream forwarder exited (channel closed)")

				// AMT closed the APF channel. Push a zero-length sentinel so the
				// receive loop asks RPS to re-handshake.
				select {
				case e.data <- nil:
				default:
				}

				return
			}

			if len(chunk) == 0 {
				continue
			}

			select {
			case e.data <- chunk:
			case <-stop:
				log.Debug("LME tunnel: stream forwarder stop while forwarding")

				return
			}
		}
	}
}

func (e *Executor) handlePortSwitch(jsonData string) error {
	var psPayload PortSwitchPayload
	if err := json.Unmarshal([]byte(jsonData), &psPayload); err != nil {
		return err
	}

	// Clamp the server-supplied delay so a hostile or buggy RPS can't block
	// the activation loop indefinitely.
	delaySeconds := psPayload.Delay
	if delaySeconds < 0 {
		delaySeconds = 0
	}

	if delaySeconds > maxPortSwitchDelaySeconds {
		log.Warnf("Port switch: server-requested delay %ds exceeds max %ds; clamping", delaySeconds, maxPortSwitchDelaySeconds)
		delaySeconds = maxPortSwitchDelaySeconds
	}

	if extraPortSwitchDelaySeconds > 0 {
		log.Infof("Port switch: adding %ds extra delay (RPC_PORT_SWITCH_EXTRA_DELAY)", extraPortSwitchDelaySeconds)

		delaySeconds += extraPortSwitchDelaySeconds
	}

	log.Infof("Port switch: waiting %ds for AMT TLS restart", delaySeconds)

	// In LME mode there is no LMS daemon to reconnect to; transport stays on
	// HECI/APF and the only thing that changes is the AMT-side port future
	// CHANNEL_OPENs target. Close-and-redial would dial a 127.0.0.1:16993
	// socket that isn't listening (that's why we're on LME in the first
	// place). Keep the LME handle, honor the delay, flip the port.
	if e.isLME {
		if err := waitWithSignal(time.Duration(delaySeconds) * time.Second); err != nil {
			return err
		}

		if lmec, ok := e.localManagement.(*lm.LMEConnection); ok {
			port, perr := strconv.ParseUint(psPayload.Port, 10, 32)
			if perr != nil {
				return fmt.Errorf("port switch: invalid port %q: %w", psPayload.Port, perr)
			}

			lmec.SetPort(uint32(port))
		}

		e.tlsTunnelActive = true

		log.Info("Port switch: LME retargeted to port ", psPayload.Port)

		ackMsg := e.payload.CreateMessageResponse([]byte("ok"), MethodPortSwitchAck)
		if err := e.server.Send(ackMsg); err != nil {
			return err
		}

		log.Info("Port switch: sent port_switch_ack to RPS")

		return nil
	}

	log.Infof("Port switch: closing LMS connection")

	// Close existing LMS connection
	e.localManagement.Close()
	e.lmConnected = false

	// Wait for AMT to restart its TLS subsystem. Use a cancellable wait so a
	// user interrupt (Ctrl+C / SIGTERM) can abort the activation loop promptly
	// instead of being delayed by the full sleep.
	if err := waitWithSignal(time.Duration(delaySeconds) * time.Second); err != nil {
		return err
	}

	// Create new LMS connection channels
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)

	// Create new plain TCP LMS connection on the TLS port.
	// rpc-go only passes raw bytes — the actual TLS handshake is handled
	// by RPS's TLSTunnelManager through the WebSocket tunnel.
	newLM := lm.NewLMSConnection(
		utils.LMSAddress,
		psPayload.Port,
		true, // useTls: gate Listen's read-timeout strategy for TLS 1.3 quiet rounds; the dial is plain TCP
		lmDataChannel,
		lmErrorChannel,
		0,     // controlMode not needed for port switch
		false, // skipCertCheck not relevant — no TLS at this layer
	)

	// Test connection with retries
	maxRetries := utils.LMEPortSwitchMaxRetries

	var connectErr error

	for i := 0; i < maxRetries; i++ {
		connectErr = newLM.Connect()
		if connectErr == nil {
			break
		}

		log.Warnf("Port switch: LMS connect attempt %d/%d failed: %v", i+1, maxRetries, connectErr)
		time.Sleep(utils.LMEPortSwitchRetryDelay * time.Second)
	}

	if connectErr != nil {
		return connectErr
	}

	// Replace the LMS connection
	e.localManagement = newLM
	e.data = lmDataChannel
	e.errors = lmErrorChannel
	e.lmConnected = true
	e.tlsTunnelActive = true
	e.localManagement.Close() // Close test connection, will reconnect on next message
	e.lmConnected = false

	log.Info("Port switch: successfully switched to port ", psPayload.Port)

	// Send port_switch_ack back to RPS
	ackMsg := e.payload.CreateMessageResponse([]byte("ok"), MethodPortSwitchAck)
	if err := e.server.Send(ackMsg); err != nil {
		return err
	}

	log.Info("Port switch: sent port_switch_ack to RPS")

	return nil
}

func (e *Executor) HandleDataFromLM(data []byte) {
	if len(data) > 0 {
		method := "response"
		if e.tlsTunnelActive {
			method = MethodTLSData
		}

		err := e.server.Send(e.payload.CreateMessageResponse(data, method))
		if err != nil {
			log.Error(err)
		}
	}
}
