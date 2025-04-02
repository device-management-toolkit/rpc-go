/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/lm"
	"github.com/sirupsen/logrus"
)

type LocalTransport struct {
	local     lm.LocalMananger
	data      chan []byte
	errors    chan error
	status    chan bool
	waitGroup *sync.WaitGroup
}

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
		logrus.Error(err)
	}

	return lm
}

// Custom dialer function
func (l *LocalTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// send channel open
	err := l.local.Connect()
	//Something comes here...Maybe
	go l.local.Listen()

	if err != nil {
		logrus.Error(err)
		return nil, err
	}
	// wait for channel open confirmation
	l.waitGroup.Wait()
	logrus.Trace("Channel open confirmation received")
	// Serialize the HTTP request to raw form
	rawRequest, err := serializeHTTPRequest(r)
	if err != nil {
		logrus.Error(err)
		return nil, err
	}

	var responseReader *bufio.Reader

	err = l.local.Send([]byte(rawRequest))
	if err != nil {
		logrus.Error(err)
		return nil, err
	}

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
				break Loop
			}
		}
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
