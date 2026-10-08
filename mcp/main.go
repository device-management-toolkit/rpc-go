/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Command rpc-mcp is a Model Context Protocol server that exposes the rpc CLI
// (Remote Provisioning Client) to AI agents. It runs on the AMT device next to the
// rpc binary and invokes it as a subprocess with --json.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName        = "rpc-mcp"
	serverVersion     = "0.1.0"
	readHeaderTimeout = 10 * time.Second
	ssePath           = "/sse"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	rpcPath := flag.String("rpc-path", envOr("RPC_PATH", "rpc"), "path to the rpc binary (env RPC_PATH)")
	devicesURL := flag.String("devices-url", os.Getenv("RPC_MCP_DEVICES_URL"),
		"Console devices API URL; enables register_device (env RPC_MCP_DEVICES_URL)")
	readOnly := flag.Bool("read-only", os.Getenv("RPC_MCP_READ_ONLY") == "true", "do not expose power_action (env RPC_MCP_READ_ONLY=true)")
	httpAddr := flag.String("http", "", "serve MCP over HTTP on this loopback address (e.g. 127.0.0.1:8090) instead of stdio: streamable HTTP at /, legacy SSE at /sse")

	flag.Parse()

	// MCP uses stdout for the protocol in stdio mode; keep our logs on stderr.
	log.SetOutput(os.Stderr)

	resolved, err := exec.LookPath(*rpcPath)
	if err != nil {
		return fmt.Errorf("rpc binary not found (%s): set --rpc-path or RPC_PATH: %w", *rpcPath, err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVersion}, nil)
	registerTools(server, NewRunner(resolved), Config{DevicesURL: *devicesURL, AllowPowerActions: !*readOnly})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if *httpAddr == "" {
		return server.Run(ctx, &mcp.StdioTransport{})
	}

	return serveHTTP(ctx, server, *httpAddr)
}

func serveHTTP(ctx context.Context, server *mcp.Server, addr string) error {
	// The HTTP endpoint has no authentication, so it must only be reachable locally.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --http address %q: %w", addr, err)
	}

	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("--http must bind to a loopback address (127.0.0.1, ::1 or localhost), got %q", host)
	}

	httpServer := &http.Server{Addr: addr, Handler: newHTTPHandler(server), ReadHeaderTimeout: readHeaderTimeout}

	go func() {
		<-ctx.Done()

		_ = httpServer.Close()
	}()

	log.Printf("%s listening on http://%s (streamable HTTP) and http://%s%s (legacy SSE)", serverName, addr, addr, ssePath)

	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

// newHTTPHandler serves both MCP HTTP transports from one listener:
//   - "/"    streamable HTTP (MCP 2025-03-26+), used by current clients;
//   - "/sse" legacy HTTP+SSE (MCP 2024-11-05) for agents that only speak SSE: GET /sse opens
//     the event stream, whose first "endpoint" event names /sse?sessionid=... for the POSTs.
//
// Both handlers keep the SDK's default DNS-rebinding protection (non-localhost Host headers
// are rejected), on top of the loopback-only bind enforced by serveHTTP.
func newHTTPHandler(server *mcp.Server) http.Handler {
	getServer := func(*http.Request) *mcp.Server { return server }

	mux := http.NewServeMux()
	mux.Handle(ssePath, mcp.NewSSEHandler(getServer, nil))
	mux.Handle("/", mcp.NewStreamableHTTPHandler(getServer, nil))

	return mux
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
