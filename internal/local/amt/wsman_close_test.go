/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/stretchr/testify/require"
)

func TestClose_ClosesIdleHTTPConnections(t *testing.T) {
	var closed atomic.Int32

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	// The WSMAN client always targets port 16992, so a keep-alive transport
	// dials the test server whatever address it is asked for.
	serverAddr := server.Listener.Addr().String()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer

			return d.DialContext(ctx, network, serverAddr)
		},
	}

	g := &GoWSMANMessages{wsmanMessages: wsman.NewMessages(client.Parameters{
		Target:    "127.0.0.1",
		Transport: transport,
	})}

	_, err := g.wsmanMessages.Client.Post("<Envelope/>")
	require.NoError(t, err)

	require.NoError(t, g.Close())

	require.Eventually(t, func() bool { return closed.Load() == 1 }, 2*time.Second, 10*time.Millisecond)
}

func TestClose_NoClient(t *testing.T) {
	g := &GoWSMANMessages{}

	require.NotPanics(t, func() { require.NoError(t, g.Close()) })
}
