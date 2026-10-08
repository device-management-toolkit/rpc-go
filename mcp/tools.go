/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// amtinfo retries GetControlMode (4 x 4s) when HECI is busy, so allow generous time.
	infoTimeout   = 90 * time.Second
	shortTimeout  = 30 * time.Second
	actionTimeout = 60 * time.Second
	wsmanTimeout  = 120 * time.Second
)

// amtinfoFields maps the get_device_info field names to rpc amtinfo flags.
var amtinfoFields = map[string]string{
	"version":           "--ver",
	"build":             "--bld",
	"sku":               "--sku",
	"uuid":              "--uuid",
	"upid":              "--upid",
	"controlMode":       "--mode",
	"provisioningState": "--provisioningState",
	"dnsSuffix":         "--dns",
	"hostname":          "--hostname",
	"lan":               "--lan",
	"remoteAccess":      "--ras",
	"operationalState":  "--operationalState",
	"certificateHashes": "--cert",
	"userCertificates":  "--userCert",
	"proxy":             "--proxy",
}

// powerActions must match the --action enum of `rpc power action`, which uses Console's
// power_action names (console/internal/controller/mcp/power_actions.go).
var powerActions = []string{
	"hibernate", "os_to_full_power", "os_to_power_saving", "power_cycle", "power_off", "power_off_soft",
	"power_on", "reset", "sleep", "soft_off", "soft_reset",
}

var errConfirmRequired = errors.New("power_action was not executed: set confirm=true after the user has explicitly approved this power action")

// Config holds server-side settings that the agent cannot override.
type Config struct {
	// DevicesURL is the Console devices API used by register_device. It is configured
	// on the server, never taken from tool input, so the agent cannot send device
	// inventory and server credentials to an arbitrary URL.
	DevicesURL string
	// AllowPowerActions enables the power_action tool.
	AllowPowerActions bool
}

// DeviceInfoInput is the input of get_device_info.
type DeviceInfoInput struct {
	Fields []string `json:"fields,omitempty" jsonschema:"subset of information to return; omit to return everything. One of: version, build, sku, uuid, upid, controlMode, provisioningState, dnsSuffix, hostname, lan, remoteAccess, operationalState, certificateHashes, userCertificates, proxy"`
}

// PowerActionInput is the input of power_action.
type PowerActionInput struct {
	Action  string `json:"action" jsonschema:"power action name as in Console: power_on, power_off, power_off_soft, soft_off, reset, soft_reset, power_cycle, sleep, hibernate, os_to_full_power or os_to_power_saving"`
	Confirm bool   `json:"confirm" jsonschema:"must be true; only set it after the user explicitly approved this action"`
}

// WSMANGetInput is the input of wsman_get.
type WSMANGetInput struct {
	Classes []string `json:"classes" jsonschema:"WSMAN class names to read, e.g. AMT_GeneralSettings, CIM_SoftwareIdentity, AMT_EthernetPortSettings"`
}

type noInput struct{}

func boolPtr(b bool) *bool { return &b }

// registerTools adds all rpc tools to the server.
func registerTools(server *mcp.Server, runner *Runner, cfg Config) {
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)}

	mcp.AddTool(server, &mcp.Tool{
		Name: "get_device_info",
		Description: "Get Intel AMT and OS information of this device by running `rpc amtinfo`: AMT version, SKU, UUID, " +
			"control mode (pre-provisioning/CCM/ACM), DNS suffix, hostname, wired/wireless LAN settings, remote access (CIRA) " +
			"status, certificate hashes and proxy settings. Works without the AMT password; without admin rights only OS-level data is returned.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in DeviceInfoInput) (*mcp.CallToolResult, any, error) {
		args, err := amtinfoArgs(in.Fields)
		if err != nil {
			return nil, nil, err
		}

		return result(runner.Run(ctx, infoTimeout, args...))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_rpc_version",
		Description: "Get the version of the rpc (Remote Provisioning Client) binary used by this server.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, any, error) {
		return result(runner.Run(ctx, shortTimeout, "version"))
	})

	// The power tools mirror Console's MCP power tools (power_get_state, power_get_capabilities,
	// power_action) but act on this device through the local AMT instead of a Console device GUID.
	mcp.AddTool(server, &mcp.Tool{
		Name: "power_get_state",
		Description: "Get the current power state of this device from Intel AMT, including its OS power-saving state. " +
			"powerState is the CIM power state (2 = on, 3/4 = sleep, 6/8 = off, 7 = hibernate); osPowerSavingState is " +
			"0 unknown, 1 unsupported, 2 full power, 3 OS power saving. Requires AMT to be activated and the AMT password configured on the server.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, any, error) {
		return result(runner.Run(ctx, shortTimeout, "power", "state"))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "power_get_capabilities",
		Description: "List the power actions this device supports (supportedActions) and Console's power capability codes. " +
			"Call this before power_action to discover valid action names for the device.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, any, error) {
		return result(runner.Run(ctx, shortTimeout, "power", "capabilities"))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "wsman_get",
		Description: "Read raw Intel AMT WSMAN classes (diagnostics) by running `rpc diagnostics wsman get`. " +
			"Requires the AMT password configured on the server.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WSMANGetInput) (*mcp.CallToolResult, any, error) {
		if len(in.Classes) == 0 {
			return nil, nil, errors.New("at least one WSMAN class is required")
		}

		args := []string{"diagnostics", "wsman", "get", "--format", "json"}
		for _, class := range in.Classes {
			args = append(args, "--class", class)
		}

		return result(runner.Run(ctx, wsmanTimeout, args...))
	})

	if cfg.DevicesURL != "" {
		mcp.AddTool(server, &mcp.Tool{
			Name: "register_device",
			Description: "Discover this device and register/sync its inventory (AMT and OS information) with the " +
				"configured Console server by running `rpc amtinfo --discover`. Returns the collected device information.",
			Annotations: &mcp.ToolAnnotations{IdempotentHint: true, OpenWorldHint: boolPtr(true)},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noInput) (*mcp.CallToolResult, any, error) {
			return result(runner.Run(ctx, infoTimeout, "amtinfo", "--discover", "--url", cfg.DevicesURL))
		})
	}

	if cfg.AllowPowerActions {
		mcp.AddTool(server, &mcp.Tool{
			Name: "power_action",
			Description: "Perform a power action on THIS device through its local Intel AMT, with the same action names and " +
				"behavior as Console's power_action. WARNING: the MCP server runs on the same machine, so power_off, reset, " +
				"power_cycle, soft_off, soft_reset, sleep and hibernate end this session and can interrupt the running OS. " +
				"Call power_get_capabilities first, ask the user to explicitly approve the action, then call with confirm=true. " +
				"Valid actions: " + strings.Join(powerActions, ", ") + ".",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in PowerActionInput) (*mcp.CallToolResult, any, error) {
			if !slices.Contains(powerActions, in.Action) {
				return nil, nil, fmt.Errorf("unsupported action %q, expected one of %v", in.Action, powerActions)
			}

			if !in.Confirm {
				return nil, nil, errConfirmRequired
			}

			return result(runner.Run(ctx, actionTimeout, "power", "action", "--action", in.Action))
		})
	}
}

func amtinfoArgs(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return []string{"amtinfo", "--all"}, nil
	}

	args := []string{"amtinfo"}

	for _, field := range fields {
		flag, ok := amtinfoFields[field]
		if !ok {
			return nil, fmt.Errorf("unknown field %q", field)
		}

		args = append(args, flag)
	}

	return args, nil
}

// result adapts Runner.Run to a tool handler return. The JSON becomes the structured
// content and, because no Content is set, the SDK also returns it as text content.
func result(out any, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		return nil, nil, err
	}

	return nil, out, nil
}
