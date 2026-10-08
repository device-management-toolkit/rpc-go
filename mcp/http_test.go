/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestHTTPTransports connects real SDK clients over both HTTP transports served by
// newHTTPHandler and calls a tool through each.
func TestHTTPTransports(t *testing.T) {
	f := &fakeRPC{stdout: `{"app":"rpc","version":"test"}`}
	server := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVersion}, nil)
	registerTools(server, newFakeRunner(f), Config{AllowPowerActions: true})

	httpServer := httptest.NewServer(newHTTPHandler(server))
	t.Cleanup(httpServer.Close)

	transports := map[string]mcp.Transport{
		"legacy SSE at /sse":   &mcp.SSEClientTransport{Endpoint: httpServer.URL + ssePath},
		"streamable HTTP at /": &mcp.StreamableClientTransport{Endpoint: httpServer.URL},
	}

	for name, transport := range transports {
		t.Run(name, func(t *testing.T) {
			client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)

			session, err := client.Connect(context.Background(), transport, nil)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}

			t.Cleanup(func() { _ = session.Close() })

			if got := toolNames(t, session); len(got) == 0 {
				t.Fatal("no tools listed")
			}

			res := callTool(t, session, "get_rpc_version", nil)
			if res.IsError || !strings.Contains(toolText(res), `"version":"test"`) {
				t.Errorf("unexpected result: %s", toolText(res))
			}
		})
	}
}

// TestSSEEndpointEvent checks the raw legacy SSE handshake an SSE-only agent relies on:
// GET /sse returns an event stream whose first event is "endpoint" with a session URL.
func TestSSEEndpointEvent(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVersion}, nil)
	httpServer := httptest.NewServer(newHTTPHandler(server))
	t.Cleanup(httpServer.Close)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+ssePath, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	buf := make([]byte, 512)

	n, err := resp.Body.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	first := string(buf[:n])
	if !strings.Contains(first, "event: endpoint") || !strings.Contains(first, ssePath+"?sessionid=") {
		t.Errorf("unexpected first event: %q", first)
	}
}

// TestSSERejectsForeignHost checks the SDK's DNS-rebinding protection stays on for /sse.
func TestSSERejectsForeignHost(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVersion}, nil)
	httpServer := httptest.NewServer(newHTTPHandler(server))
	t.Cleanup(httpServer.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, httpServer.URL+ssePath, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Host = "attacker.example.com"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}
