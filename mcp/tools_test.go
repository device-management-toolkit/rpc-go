/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect starts the server with the given config over in-memory transports.
func connect(t *testing.T, f *fakeRPC, cfg Config) *mcp.ClientSession {
	t.Helper()

	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVersion}, nil)
	registerTools(server, newFakeRunner(f), cfg)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)

	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = session.Close() })

	return session
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}

	return res
}

func toolText(res *mcp.CallToolResult) string {
	var sb strings.Builder

	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}

	return sb.String()
}

func toolNames(t *testing.T, session *mcp.ClientSession) []string {
	t.Helper()

	list, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	names := make([]string, 0, len(list.Tools))
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}

	slices.Sort(names)

	return names
}

func TestToolRegistration(t *testing.T) {
	all := connect(t, &fakeRPC{}, Config{DevicesURL: "https://console/api/v1/devices", AllowPowerActions: true})
	if got, want := toolNames(t, all), []string{"get_device_info", "get_power_state", "get_rpc_version", "power_action", "register_device", "wsman_get"}; !slices.Equal(got, want) {
		t.Errorf("tools = %v, want %v", got, want)
	}

	readOnly := connect(t, &fakeRPC{}, Config{})
	if got, want := toolNames(t, readOnly), []string{"get_device_info", "get_power_state", "get_rpc_version", "wsman_get"}; !slices.Equal(got, want) {
		t.Errorf("tools = %v, want %v", got, want)
	}
}

func TestGetDeviceInfo(t *testing.T) {
	f := &fakeRPC{stdout: `{"amt":"16.1.25","controlMode":"activated in client control mode"}`}
	session := connect(t, f, Config{})

	res := callTool(t, session, "get_device_info", map[string]any{"fields": []string{"version", "controlMode"}})
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", toolText(res))
	}

	if want := []string{"amtinfo", "--ver", "--mode", "--json"}; !slices.Equal(f.args, want) {
		t.Errorf("args = %v, want %v", f.args, want)
	}

	if !strings.Contains(toolText(res), "16.1.25") {
		t.Errorf("unexpected content %q", toolText(res))
	}

	callTool(t, session, "get_device_info", nil)

	if want := []string{"amtinfo", "--all", "--json"}; !slices.Equal(f.args, want) {
		t.Errorf("args = %v, want %v", f.args, want)
	}

	if res := callTool(t, session, "get_device_info", map[string]any{"fields": []string{"bogus"}}); !res.IsError {
		t.Error("expected error for unknown field")
	}
}

func TestPowerAction(t *testing.T) {
	f := &fakeRPC{stdout: `{"action":"reset","status":"success"}`}
	session := connect(t, f, Config{AllowPowerActions: true})

	res := callTool(t, session, "power_action", map[string]any{"action": "reset"})
	if !res.IsError || f.args != nil {
		t.Fatal("power_action without confirm must not run rpc")
	}

	if res := callTool(t, session, "power_action", map[string]any{"action": "explode", "confirm": true}); !res.IsError || f.args != nil {
		t.Fatal("unsupported action must not run rpc")
	}

	res = callTool(t, session, "power_action", map[string]any{"action": "reset", "confirm": true})
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", toolText(res))
	}

	if want := []string{"power", "action", "--state", "reset", "--json"}; !slices.Equal(f.args, want) {
		t.Errorf("args = %v, want %v", f.args, want)
	}
}

func TestRegisterDeviceUsesConfiguredURL(t *testing.T) {
	f := &fakeRPC{stdout: `{"uuid":"abc"}`}
	session := connect(t, f, Config{DevicesURL: "https://console/api/v1/devices"})

	callTool(t, session, "register_device", nil)

	if want := []string{"amtinfo", "--discover", "--url", "https://console/api/v1/devices", "--json"}; !slices.Equal(f.args, want) {
		t.Errorf("args = %v, want %v", f.args, want)
	}
}

func TestRPCFailureIsToolError(t *testing.T) {
	f := &fakeRPC{exitCode: 10, stderr: `{"level":"error","msg":"Error 1: IncorrectPermissions"}`}
	session := connect(t, f, Config{})

	res := callTool(t, session, "get_power_state", nil)
	if !res.IsError || !strings.Contains(toolText(res), "IncorrectPermissions") || !strings.Contains(toolText(res), "elevated") {
		t.Errorf("expected tool error, got %+v", res)
	}
}
