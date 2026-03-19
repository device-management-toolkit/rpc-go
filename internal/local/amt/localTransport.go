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

type LocalTransport struct {
	local     lm.LocalMananger
	data      chan []byte
	errors    chan error
	status    chan bool
	waitGroup *sync.WaitGroup
}

const maxChannelOpenBusyRetries = 2

func NewLocalTransport() *LocalTransport {
	lmDataChannel := make(chan []byte)
	lmErrorChannel := make(chan error)
	waiter := &sync.WaitGroup{}
	lm := &LocalTransport{
		local:     lm.NewLMEConnection(lmDataChannel, lmErrorChannel, waiter),
		data:      lmDataChannel,
		errors:    lmErrorChannel,
		waitGroup: waiter,
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
	var err error
	for attempt := 0; attempt <= maxChannelOpenBusyRetries; attempt++ {
		err = l.local.Connect()
		if err == nil {
			break
		}

		if !isMEIDeviceBusyError(err) || attempt == maxChannelOpenBusyRetries {
			logrus.Error(err)

			return nil, err
		}

		wait := time.Duration(attempt+1) * time.Duration(utils.HeciConnectRetryBackoff) * time.Millisecond
		logrus.Warnf("mei busy during channel open, retry %d/%d", attempt+1, maxChannelOpenBusyRetries)
		time.Sleep(wait)
	}

	go l.local.Listen()

	channelOpenTimeout := time.Duration(utils.LMETimerTimeout) * time.Second
	if channelOpenTimeout <= 0 || channelOpenTimeout > utils.AMTResponseTimeout*time.Second {
		channelOpenTimeout = utils.AMTResponseTimeout * time.Second
	}

	channelOpenTimer := time.After(channelOpenTimeout)

	channelOpenDone := make(chan struct{})

	go func() {
		defer close(channelOpenDone)

		l.waitGroup.Wait()
	}()

	select {
	case <-channelOpenDone:
	case <-channelOpenTimer:
		return nil, fmt.Errorf("timeout waiting for LME channel open confirmation after %s", channelOpenTimeout)
	}

	logrus.Trace("Channel open confirmation received")
	// Serialize the HTTP request to raw form
	rawRequest, err := serializeHTTPRequest(r)
	if err != nil {
		logrus.Error(err)

		return nil, err
	}

	var (
		responseReader *bufio.Reader
		respErr        error
	)

	err = l.local.Send(rawRequest)
	if err != nil {
		logrus.Error(err)

		return nil, err
	}

	responseTimeout := utils.AMTResponseTimeout * time.Second

	responseTimer := time.After(responseTimeout)

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
		case <-responseTimer:
			respErr = fmt.Errorf("timeout waiting for LME response after %s", responseTimeout)

			break Loop
		}
	}

	// If we exited without any data, propagate the last error (or a generic one) instead of panicking.
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

func serializeHTTPRequest(r *http.Request) ([]byte, error) {
	var reqBuffer bytes.Buffer

	r.Header.Set("Transfer-Encoding", "chunked")

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

func isMEIDeviceBusyError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := strings.ToLower(err.Error())

	return strings.Contains(errMsg, "device or resource busy") || strings.Contains(errMsg, "resource busy")
}
