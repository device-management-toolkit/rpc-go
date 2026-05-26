/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"bufio"
	"bytes"
	"context"
	cryptotls "crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

// lmeInitializer creates and APF-handshakes an LME session over a fresh HECI
// handle. It is a package var so tests can substitute an in-memory HECI fake.
var lmeInitializer = func() (*lm.LMEConnection, error) {
	lme := lm.NewLMEConnection(make(chan []byte, 1), make(chan error, 1), &sync.WaitGroup{})
	if err := lme.Initialize(); err != nil {
		_ = lme.Close()

		return nil, fmt.Errorf("initialize LME: %w", err)
	}

	return lme, nil
}

// LocalTLSTransport is an http.RoundTripper that reaches AMT's TLS local port
// (16993) over the LME/APF path on the HECI driver, for AMT 19+ devices that
// enforce TLS on local ports when the LMS daemon is not listening.
//
// Each WSMAN request gets its own short-lived LME session: bring up the APF
// handshake on a fresh HECI handle, open one forwarded-tcpip channel to 16993,
// run a TLS session over it (handshake + encrypted HTTP), read the full
// response, then release the handle. Closing the handle per request discards any
// frames AMT has queued (notably a trailing CHANNEL_CLOSE ack), so nothing can
// bleed into the next request — which a single reused handle could not guarantee,
// since AMT's per-channel close acks race across channel boundaries. Requests are
// serialized; the per-request handshake is negligible next to the TLS handshake
// that each request performs anyway.
type LocalTLSTransport struct {
	tlsConfig *cryptotls.Config

	mu sync.Mutex // serializes requests; AMT serves one LME session at a time
}

// NewLocalTLSTransport returns a transport that tunnels TLS-wrapped WSMAN to AMT
// on port 16993 over the LME/APF path.
func NewLocalTLSTransport(tlsConfig *cryptotls.Config) *LocalTLSTransport {
	return &LocalTLSTransport{tlsConfig: tlsConfig}
}

// RoundTrip runs one WSMAN request over a dedicated LME session + APF channel +
// TLS session.
func (t *LocalTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rawRequest, err := serializeHTTPRequest(req)
	if err != nil {
		return nil, err
	}

	lme, err := lmeInitializer()
	if err != nil {
		return nil, err
	}

	// Release the HECI handle when the request completes. Dropping the handle
	// discards any frames AMT still has queued so they can't poison the next
	// request's session.
	defer func() { _ = lme.Close() }()

	conn, err := lm.DialAPF(lme.Command, 1, utils.LMSTLSPortNum)
	if err != nil {
		return nil, fmt.Errorf("open APF channel to AMT TLS port: %w", err)
	}

	defer func() { _ = conn.Close() }()

	return t.exchange(req, conn, rawRequest)
}

// exchange performs the TLS handshake and a single HTTP request/response over the
// APF channel, buffering the response body so the channel can be closed before
// returning to the caller.
func (t *LocalTLSTransport) exchange(req *http.Request, conn *lm.APFConn, rawRequest []byte) (*http.Response, error) {
	timeout := time.Duration(utils.AMTResponseTimeout) * time.Second

	hsCtx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()

	tlsConn := cryptotls.Client(conn, t.tlsConfig)
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		return nil, fmt.Errorf("tls handshake over LME: %w", err)
	}

	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if _, err := tlsConn.Write(rawRequest); err != nil {
		return nil, fmt.Errorf("write request over LME-TLS: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		return nil, fmt.Errorf("read response over LME-TLS: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("read response body over LME-TLS: %w", err)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))

	return resp, nil
}

// Close is a no-op: each request owns and releases its own HECI session, so the
// transport holds no persistent handle. It exists to satisfy io.Closer.
func (t *LocalTLSTransport) Close() error {
	return nil
}
