# rpc-mcp implementation recipes

These templates are taken from the existing code (`mcp/tools.go`, `mcp/runner.go`, `internal/commands/power.go`). Before copying, check them against the current files in case the code has moved on.

## Tool template

Read-only tool backed by an rpc command (in `registerTools`, `mcp/tools.go`):

```go
// Input: every field that reaches rpc argv must be validated.
type BootOptionsInput struct {
	Source string `json:"source,omitempty" jsonschema:"one of: pxe, hdd, cd"`
}

mcp.AddTool(server, &mcp.Tool{
	Name:        "get_boot_options",
	Description: "What it returns, which rpc command it runs, and prerequisites (activation, AMT password).",
	Annotations: readOnly, // &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)}
}, func(ctx context.Context, _ *mcp.CallToolRequest, in BootOptionsInput) (*mcp.CallToolResult, any, error) {
	if in.Source != "" && !slices.Contains(bootSources, in.Source) {
		return nil, nil, fmt.Errorf("unsupported source %q, expected one of %v", in.Source, bootSources)
	}

	return result(runner.Run(ctx, shortTimeout, "boot", "options"))
})
```

Tools with no input use `_ noInput`. A returned `error` becomes an `isError` tool result; return `*jsonrpc.Error` only for protocol-level faults.

Destructive tool: gate it, and add it only when `cfg.AllowPowerActions` (or a new `cfg.AllowX`) is set:

```go
if cfg.AllowPowerActions {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_next_boot",
		Description: "... Ask the user to explicitly approve, then call with confirm=true. Explain the side effects.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SetBootInput) (*mcp.CallToolResult, any, error) {
		if !slices.Contains(bootSources, in.Source) { // validate first, so a bad input never reaches rpc
			return nil, nil, fmt.Errorf("unsupported source %q", in.Source)
		}

		if !in.Confirm {
			return nil, nil, errConfirmRequired
		}

		return result(runner.Run(ctx, actionTimeout, "boot", "set", "--source", in.Source))
	})
}
```

A tool that sends data off the device takes its target from `Config` (set by a server flag or env var), never from the input. See `register_device`, which uses `cfg.DevicesURL`.

### Tool test template (`mcp/tools_test.go`)

```go
func TestGetBootOptions(t *testing.T) {
	f := &fakeRPC{stdout: `{"source":"hdd"}`}
	session := connect(t, f, Config{})

	res := callTool(t, session, "get_boot_options", nil)
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", toolText(res))
	}

	if want := []string{"boot", "options", "--json"}; !slices.Equal(f.args, want) {
		t.Errorf("args = %v, want %v", f.args, want)
	}
}
```

For gated tools, also assert that `f.args == nil` when `confirm` is missing or the input is invalid, which proves rpc was never run. Update `TestToolRegistration` whenever the tool list changes.

## rpc command template

This is the D4 pattern; see `internal/commands/power.go`. Put the file under `internal/commands/` and register it in `internal/cli/cli.go`.

```go
type BootCmd struct {
	Options BootOptionsCmd `cmd:"" name:"options" help:"Show AMT boot options"`
}

type BootOptionsCmd struct {
	AMTBaseCmd
}

func (cmd *BootOptionsCmd) Run(ctx *Context) error {
	if cmd.ControlMode == 0 {
		return utils.DeviceNotActivated
	}

	if err := cmd.EnsureAMTPassword(ctx, cmd); err != nil {
		return err
	}

	if err := cmd.EnsureWSMAN(ctx); err != nil {
		return err
	}

	resp, err := cmd.WSMan.GetBootSettingData() // new WSMANer method, then `make mock`
	if err != nil {
		return utils.CustomError{Code: utils.WSMANMessageError.Code, Message: utils.WSMANMessageError.Message, Details: err.Error()}
	}

	result := BootOptionsResult{ /* map resp fields; JSON tags in camelCase */ }

	// writePowerOutput is a generic JSON/text writer in power.go; reuse it or move it to a shared helper.
	return writePowerOutput(os.Stdout, ctx.JsonOutput, result, func(w io.Writer) {
		fmt.Fprint(w, renderInfoHeader("BOOT OPTIONS"))
		fmt.Fprint(w, renderInfoRow("Source", result.Source))
	})
}
```

Rules:
- Return `utils.CustomError` values, with `Details` where useful, so the exit code reaches rpc-mcp. Plain errors become GenericFailure (10).
- If the firmware returns a `ReturnValue`, check it, and turn a non-zero value into a typed error that includes `ReturnValue.String()`.
- Only JSON goes to stdout in `--json` mode. Logs go through logrus, which writes JSON to stderr in `--json` mode.
- Use subtests with gomock `NewMockWSMANer`, and set `AMTBaseCmd{ControlMode: 1, WSMan: mock}` and `Context{AMTPassword: "pw"}` to skip the prompt and the WSMAN setup.

## Runner hints

Add an entry to `exitCodeHints` in `mcp/runner.go` when a new `utils.CustomError` code is likely, so the agent gets an actionable message. Codes are listed in `pkg/utils/constants.go`.

## Documentation updates per change

| Change | README | ARCHITECTURE.md |
|---|---|---|
| New or changed tool | Capabilities table, tool inputs, troubleshooting | D5 table, diagram §3, plus a sequence diagram if the flow is new |
| New rpc command | Prerequisites, if the rpc version matters | D4 table, diagram §2 (mark the new nodes `:::new`) |
| New flag or env var | Configuration table, client config examples | Decision text if it affects safety (D6) |
| Design change | Anything user-visible | New decision `D9…` plus updated diagrams |
