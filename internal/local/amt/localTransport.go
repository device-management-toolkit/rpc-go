/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/sirupsen/logrus"
)

// listenSafetyTimeout guards against Listen exiting without signaling, leaving RoundTrip blocked.
// Derived from utils.LMEChannelOpenTimeout so executor and localTransport share a
// single source of truth for the value.
var listenSafetyTimeout = utils.LMEChannelOpenTimeout * time.Second

// localLMEListenStopTimeout bounds how long LocalTransport waits for a prior
// persistent LME Listen goroutine to exit after StopListen is signaled.
var localLMEListenStopTimeout = (utils.HeciReadTimeout + 1) * time.Second

type LocalTransport struct {
	local     lm.LocalMananger
	lme       *lm.LMEConnection // underlying LME session; TLS path uses it directly
	data      chan []byte
	errors    chan error
	tlsConfig *cryptotls.Config

	lmeListenMu   sync.Mutex
	lmeListenDone chan struct{}
	tlsStateMu    sync.RWMutex
	lastCertHash  string
}

// NewLocalTransport returns a LocalTransport that speaks cleartext HTTP over
// an APF channel on the AMT HTTP port (16992).
func NewLocalTransport() *LocalTransport {
	return newLocalTransport(nil, amtHTTPPort)
}

// NewLocalTransportTLS returns a LocalTransport that opens an APF channel to
// the AMT TLS port (16993) and terminates AMT's TLS inside this process using
// the supplied tls.Config, so HTTP/WSMAN traffic can be sent over the encrypted
// stream. Used as the fallback when no LMS daemon is listening on the device.
func NewLocalTransportTLS(tlsConfig *cryptotls.Config) *LocalTransport {
	return newLocalTransport(tlsConfig, amtHTTPSPort)
}

const (
	amtHTTPPort  uint32 = 16992
	amtHTTPSPort uint32 = 16993
)

func newLocalTransport(tlsConfig *cryptotls.Config, port uint32) *LocalTransport {
	lmDataChannel := make(chan []byte, 1)
	lmErrorChannel := make(chan error, 1)
	// A throwaway WG keeps the NewLMEConnection signature happy; each RoundTrip
	// attempt installs a fresh WG via resetHandshake so a stuck counter from a
	// prior failed attempt can't deadlock the next one.
	conn := lm.NewLMEConnection(lmDataChannel, lmErrorChannel, &sync.WaitGroup{})
	conn.SetPort(port)

	t := &LocalTransport{
		local:     conn,
		lme:       conn,
		data:      lmDataChannel,
		errors:    lmErrorChannel,
		tlsConfig: tlsConfig,
	}

	err := t.local.Initialize()
	if err != nil {
		if heci.IsReadTimeout(err) {
			logrus.Warn(err)
		} else {
			logrus.Error(err)
		}
	}

	return t
}

// Close closes the LME connection and releases the MEI device
func (l *LocalTransport) Close() error {
	l.stopLMEListen()

	if l.local != nil {
		return l.local.Close()
	}

	return nil
}

// Custom dialer function
func (l *LocalTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Serialize once so retries resend the same pre-chunked bytes.
	rawRequest, err := serializeHTTPRequest(r)
	if err != nil {
		logrus.Error(err)

		return nil, err
	}

	const maxAttempts = 2

	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var (
			resp *http.Response
			err  error
		)

		if l.tlsConfig != nil {
			resp, err = l.attemptTLSRoundTrip(r, rawRequest)
		} else {
			resp, err = l.attemptRoundTrip(r, rawRequest)
		}

		if err == nil {
			return resp, nil
		}

		lastErr = err

		if attempt == maxAttempts || !isTransientLMEError(err) {
			break
		}

		logrus.Warnf("LME round-trip attempt %d/%d failed (%v); resetting HECI and retrying", attempt, maxAttempts, err)

		// Close MEI to unblock the prior Listen goroutine, then reinit for a clean APF handshake.
		_ = l.local.Close()

		if initErr := l.local.Initialize(); initErr != nil {
			logrus.Warnf("reinitializing LME after transient error failed: %v", initErr)

			return nil, fmt.Errorf("reinitialize LME: %w", initErr)
		}
	}

	return nil, lastErr
}

// attemptRoundTrip runs one Connect → Send → receive cycle over the APF channel.
func (l *LocalTransport) attemptRoundTrip(r *http.Request, rawRequest []byte) (resp *http.Response, err error) {
	// Fresh handshake WaitGroup per attempt: if a prior Listen exited without
	// signaling Done(), the old WG is abandoned rather than deadlocking this one.
	handshake := l.resetHandshake()

	if err := l.local.Connect(); err != nil {
		logrus.Error(err)

		return nil, err
	}

	go l.local.Listen()

	// Wait for channel open confirmation (or open failure, which also calls Done()).
	// Bounded so a Listen goroutine that exits early on a HECI error can't block forever.
	handshakeDone := lm.WaitChan(handshake)

	select {
	case <-handshakeDone:
		logrus.Trace("Channel open confirmation received")
	case errFromLMS := <-l.errors:
		if errFromLMS != nil {
			return nil, errFromLMS
		}
	case <-time.After(listenSafetyTimeout):
		return nil, fmt.Errorf("timed out waiting for APF channel open after %s", listenSafetyTimeout)
	}

	// Surface any APF_CHANNEL_OPEN_FAILURE that arrived alongside handshake completion.
	select {
	case errFromLMS := <-l.errors:
		if errFromLMS != nil {
			return nil, errFromLMS
		}
	default:
	}

	if err := l.local.Send(rawRequest); err != nil {
		logrus.Error(err)

		return nil, err
	}

	var (
		responseReader *bufio.Reader
		respErr        error
	)

Loop:
	for {
		select {
		case dataFromLM := <-l.data:
			if len(dataFromLM) > 0 {
				logrus.WithField("payload_bytes", len(dataFromLM)).Debug("received data from LME")
				responseReader = bufio.NewReader(bytes.NewReader(dataFromLM))

				break Loop
			}
		case errFromLMS := <-l.errors:
			if errFromLMS != nil {
				logrus.Error("error from LMS")

				respErr = errFromLMS
			}

			break Loop
		case <-time.After(listenSafetyTimeout):
			// Listen stalled without signaling; treat as transient so retry resets HECI.
			respErr = fmt.Errorf("no response from LME within %s", listenSafetyTimeout)

			break Loop
		}
	}

	if responseReader == nil {
		if respErr == nil {
			respErr = fmt.Errorf("no response from LME")
		}

		return nil, respErr
	}

	response, err := http.ReadResponse(responseReader, r)
	if err != nil {
		logrus.Error("Failed to parse response: ", err)

		return nil, err
	}

	return response, nil
}

// attemptTLSRoundTrip opens an APF channel to AMT's TLS port, runs a TLS
// handshake over it using NewAPFChannelConn as the underlying net.Conn, then
// writes the pre-serialized HTTP request and reads the HTTP response back
// through the TLS connection. Used when the device has no LMS daemon listening
// on :16993 but TLS is enforced on the local AMT ports.
func (l *LocalTransport) attemptTLSRoundTrip(r *http.Request, rawRequest []byte) (*http.Response, error) {
	if l.lme == nil {
		return nil, errors.New("TLS LocalTransport requires an LMEConnection")
	}

	handshake := l.resetHandshake()

	l.stopLMEListen()
	apfConn := lm.NewAPFChannelConn(l.lme)

	if err := l.lme.Connect(); err != nil {
		return nil, err
	}

	l.startLMEListen()

	handshakeDone := lm.WaitChan(handshake)

	select {
	case <-handshakeDone:
		logrus.Trace("APF channel open confirmation received (TLS path)")
	case errFromLMS := <-l.errors:
		if errFromLMS != nil {
			return nil, errFromLMS
		}
	case <-time.After(listenSafetyTimeout):
		return nil, fmt.Errorf("timed out waiting for APF channel open after %s", listenSafetyTimeout)
	}

	tlsConn := cryptotls.Client(apfConn, l.tlsConfig)
	if err := tlsConn.SetDeadline(time.Now().Add(listenSafetyTimeout)); err != nil {
		_ = tlsConn.Close()

		return nil, err
	}

	handshakeCtx, cancel := context.WithTimeout(context.Background(), listenSafetyTimeout)
	defer cancel()

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("AMT TLS handshake over APF channel failed: %w", err)
	}

	state := tlsConn.ConnectionState()
	l.captureServerCertificate(state.PeerCertificates)
	logrus.Debugf("AMT TLS handshake over APF complete (version=0x%x, cipher=0x%x)", state.Version, state.CipherSuite)

	if _, err := tlsConn.Write(rawRequest); err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("write request over AMT TLS: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), r)
	if err != nil {
		_ = tlsConn.Close()

		return nil, fmt.Errorf("read response over AMT TLS: %w", err)
	}

	// Drain and re-buffer the body so we can close the TLS connection and the
	// underlying APF channel before returning to the caller.
	body, readErr := io.ReadAll(resp.Body)

	_ = resp.Body.Close()
	_ = tlsConn.Close()

	if readErr != nil {
		return nil, fmt.Errorf("read response body over AMT TLS: %w", readErr)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))

	return resp, nil
}

// stopLMEListen retires LocalTransport's prior persistent LME listener and
// waits for exit so a new TLS round never races a second Receive loop on the
// same HECI handle.
func (l *LocalTransport) stopLMEListen() {
	l.lmeListenMu.Lock()
	done := l.lmeListenDone
	l.lmeListenMu.Unlock()

	if done == nil || l.lme == nil {
		return
	}

	l.lme.StopListen()

	select {
	case <-done:
	case <-time.After(localLMEListenStopTimeout):
		logrus.Warn("LocalTransport TLS path: timed out waiting for previous LME listener to exit")
	}

	l.lmeListenMu.Lock()
	if l.lmeListenDone == done {
		l.lmeListenDone = nil
	}
	l.lmeListenMu.Unlock()
}

func (l *LocalTransport) startLMEListen() {
	done := make(chan struct{})

	l.lmeListenMu.Lock()
	l.lmeListenDone = done
	l.lmeListenMu.Unlock()

	go func() {
		l.lme.Listen()
		close(done)
	}()
}

// resetHandshake installs a fresh WaitGroup on the LME session so the current
// round-trip attempt starts from a known-zero counter. On non-LME transports
// the WaitGroup is returned but not wired through; the attempt's timeout guards
// it regardless.
func (l *LocalTransport) resetHandshake() *sync.WaitGroup {
	if lmec, ok := l.local.(*lm.LMEConnection); ok {
		return lmec.ResetHandshake()
	}

	return &sync.WaitGroup{}
}

func (l *LocalTransport) captureServerCertificate(certs []*x509.Certificate) {
	if len(certs) == 0 {
		return
	}

	hash := sha256.Sum256(certs[0].Raw)

	l.tlsStateMu.Lock()
	l.lastCertHash = hex.EncodeToString(hash[:])
	l.tlsStateMu.Unlock()
}

func (l *LocalTransport) LastServerCertificateFingerprint() string {
	l.tlsStateMu.RLock()
	defer l.tlsStateMu.RUnlock()

	return l.lastCertHash
}

// isTransientLMEError reports whether err is a retryable APF/HTTP hiccup (EOF, channel refusal).
func isTransientLMEError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}

	msg := err.Error()

	return strings.Contains(msg, "unexpected EOF") ||
		strings.Contains(msg, "no response from LME") ||
		// APF_CHANNEL_OPEN_FAILURE; AMT transiently refuses channels under back-to-back opens.
		strings.Contains(msg, "error opening APF channel")
}

func serializeHTTPRequest(r *http.Request) ([]byte, error) {
	var reqBuffer bytes.Buffer

	r.Header.Set("Transfer-Encoding", "chunked")
	// Connection: close — otherwise AMT keeps the APF channel open and the client hangs.
	r.Header.Set("Connection", "close")

	// Write request line
	reqLine := fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
	reqBuffer.WriteString(reqLine)

	// Write headers
	r.Header.Write(&reqBuffer)
	reqBuffer.WriteString("\r\n") // End of headers

	// Write body if present
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}

		length := fmt.Sprintf("%x", len(bodyBytes))
		bodyBytes = append([]byte(length+"\r\n"), bodyBytes...)
		bodyBytes = append(bodyBytes, []byte("\r\n0\r\n\r\n")...)
		// Important: Replace the body so it can be read again later if needed
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		reqBuffer.Write(bodyBytes)
	}

	return reqBuffer.Bytes(), nil
}
