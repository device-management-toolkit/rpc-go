/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"bufio"
	"bytes"
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
var listenSafetyTimeout = (utils.HeciReadTimeout + 15) * time.Second

type LocalTransport struct {
	local  lm.LocalMananger
	data   chan []byte
	errors chan error
	status chan bool
}

func NewLocalTransport() *LocalTransport {
	lmDataChannel := make(chan []byte, 1)
	lmErrorChannel := make(chan error, 1)
	// A throwaway WG keeps the NewLMEConnection signature happy; each RoundTrip
	// attempt installs a fresh WG via resetHandshake so a stuck counter from a
	// prior failed attempt can't deadlock the next one.
	lm := &LocalTransport{
		local:  lm.NewLMEConnection(lmDataChannel, lmErrorChannel, &sync.WaitGroup{}),
		data:   lmDataChannel,
		errors: lmErrorChannel,
	}
	// defer lm.local.Close()
	// defer close(lmDataChannel)
	// defer close(lmErrorChannel)
	// defer close(lmStatus)

	err := lm.local.Initialize()
	if err != nil {
		if errors.Is(err, heci.ErrReadTimeout) || strings.Contains(err.Error(), "heci read timeout") {
			logrus.Warn(err)
		} else {
			logrus.Error(err)
		}
	}

	return lm
}

// Close closes the LME connection and releases the MEI device
func (l *LocalTransport) Close() error {
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
		resp, err := l.attemptRoundTrip(r, rawRequest)
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

	// Drain the WG on the way out so the goroutine waiting on it never leaks,
	// even when Listen exits before the APF handshake completes.
	defer func() {
		defer func() { _ = recover() }()

		handshake.Done()
	}()

	if err := l.local.Connect(); err != nil {
		logrus.Error(err)

		return nil, err
	}

	go l.local.Listen()

	// Wait for channel open confirmation (or open failure, which also calls Done()).
	// Bounded so a Listen goroutine that exits early on a HECI error can't block forever.
	handshakeDone := make(chan struct{})

	go func() {
		handshake.Wait()
		close(handshakeDone)
	}()

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
				logrus.Debug("received data from LME")
				logrus.Trace(string(dataFromLM))
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

// resetHandshake installs a fresh WaitGroup on the LME session so the current
// round-trip attempt starts from a known-zero counter. On non-LME transports
// the WaitGroup is returned but not wired through; the attempt's timeout guards
// it regardless.
func (l *LocalTransport) resetHandshake() *sync.WaitGroup {
	wg := &sync.WaitGroup{}

	if lmec, ok := l.local.(*lm.LMEConnection); ok && lmec.Session != nil {
		lmec.Session.WaitGroup = wg
	}

	return wg
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
