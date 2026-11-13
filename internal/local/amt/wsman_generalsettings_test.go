/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureTransport struct {
	body string
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	c.body = string(b)

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/soap+xml"}},
		Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0" encoding="UTF-8"?><a:Envelope xmlns:a="http://www.w3.org/2003/05/soap-envelope"><a:Header></a:Header><a:Body></a:Body></a:Envelope>`)),
		Request:    req,
	}, nil
}

func TestPutGeneralSettings_SetsNamespace(t *testing.T) {
	transport := &captureTransport{}
	g := &GoWSMANMessages{wsmanMessages: wsman.NewMessages(client.Parameters{Target: "localhost", Transport: transport})}

	_, err := g.PutGeneralSettings(general.GeneralSettingsRequest{HostName: "host"})
	require.NoError(t, err)

	assert.Contains(t, transport.body, `<h:AMT_GeneralSettings xmlns:h="http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings">`)
}
