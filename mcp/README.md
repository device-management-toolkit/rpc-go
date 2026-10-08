# rpc-mcp: MCP server for rpc-go

`rpc-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server. It lets an AI agent (Claude Code, Claude Desktop, VS Code / GitHub Copilot, or any other MCP client) read Intel® AMT device information and perform power actions through **rpc** (the Remote Provisioning Client).

It runs **on the AMT device itself**, next to the `rpc` binary. Each tool call runs `rpc <command> ... --json` as a subprocess and returns the JSON result to the agent. rpc-mcp does not import any rpc-go code, so it builds and ships on its own.

```
AI agent / MCP client ──stdio or local HTTP──> rpc-mcp ──exec "rpc ... --json"──> rpc ──MEI/LMS/WSMAN──> Intel AMT
```

The design rationale is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**New here?** Follow [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md). It walks through building rpc and rpc-mcp for Windows and Linux, deploying them, running them, and connecting Claude Code, GitHub Copilot (VS Code and CLI) or Claude Desktop. Ready-to-copy agent configs are in [examples/](examples/).

## Capabilities

| Tool | What it does | rpc command | Kind | Needs AMT password |
|---|---|---|---|---|
| `get_device_info` | AMT version, build, SKU, UUID, UPID, control mode, provisioning state, DNS suffix, hostname, wired/wireless LAN settings, remote access (CIRA) status, operational state, certificate hashes, user certificates, proxy settings. Optional `fields` selects a subset. | `amtinfo --all` or `amtinfo --<flag>...` | read-only | no (only for `userCertificates` / `proxy`) |
| `get_rpc_version` | Version of the rpc binary in use. | `version` | read-only | no |
| `power_get_state` | AMT power state (`powerState`, CIM value) and the OS power-saving state (`osPowerSavingState`). Same output as Console's `power_get_state`. | `power state` | read-only | yes |
| `power_get_capabilities` | Power actions this device supports (`supportedActions`), plus Console's capability codes. Same logic as Console's `power_get_capabilities`. | `power capabilities` | read-only | yes |
| `wsman_get` | Raw read of one or more AMT WSMAN classes (diagnostics), e.g. `AMT_GeneralSettings`. | `diagnostics wsman get --class ...` | read-only | yes |
| `register_device` | Discovers this device and registers or syncs its inventory with Console. Only listed when `--devices-url` is configured. | `amtinfo --discover --url <devices-url>` | writes to Console | no |
| `power_action` | Performs a power action with Console's action names and behavior: `power_on`, `power_off`, `power_off_soft`, `soft_off`, `reset`, `soft_reset`, `power_cycle`, `sleep`, `hibernate`, `os_to_full_power`, `os_to_power_saving`. Requires `confirm: true`. Not listed with `--read-only`. | `power action --action <name>` | **destructive** | yes |

All power tools run **locally**: rpc sends WSMAN to this device's own AMT firmware through LMS on `127.0.0.1`, or through HECI when LMS isn't installed. No Console is involved. The action names, codes and behavior are copied from Console (`console/internal/usecase/devices/power.go`), so the agent gets the same results it would get through Console. See [ARCHITECTURE.md D9](docs/ARCHITECTURE.md#d9-power-behavior-mirrors-console-executed-locally).

### Tool inputs

- `get_device_info`: `{"fields": ["version", "controlMode", "lan"]}`. All fields are optional. The supported names are `version`, `build`, `sku`, `uuid`, `upid`, `controlMode`, `provisioningState`, `dnsSuffix`, `hostname`, `lan`, `remoteAccess`, `operationalState`, `certificateHashes`, `userCertificates` and `proxy`.
- `wsman_get`: `{"classes": ["AMT_GeneralSettings", "CIM_SoftwareIdentity"]}`
- `power_action`: `{"action": "reset", "confirm": true}`
- `get_rpc_version`, `power_get_state`, `power_get_capabilities` and `register_device` take no input.

### Tool output

Each tool returns the JSON that `rpc ... --json` prints. It is sent both as MCP *structured content* and as a text content block. For example:

```jsonc
// power_get_state
{ "powerState": 2, "osPowerSavingState": 2 }

// power_get_capabilities (AMT 16 with BIOS setup support)
{
  "supportedActions": ["hibernate", "power_cycle", "power_off", "power_on", "reset", "sleep", "soft_off", "soft_reset"],
  "capabilities": { "Power up": 2, "Power cycle": 5, "Power down": 8, "Reset": 10, "Soft-off": 12, "Soft-reset": 14,
                    "Sleep": 4, "Hibernate": 7, "Power up to BIOS": 100, "Reset to BIOS": 101, "Reset to PXE": 400, "...": "..." }
}

// power_action {"action": "reset", "confirm": true}
{ "action": "reset", "code": 10, "returnValue": 0 }
```

- **`powerState`** is the DMTF CIM value: 2 on, 3/4 sleep, 6/8 off, 7 hibernate.
- **`osPowerSavingState`** is 0 unknown, 1 unsupported, 2 full power, 3 OS power saving.
- **`capabilities`** uses Console's keys and codes. The boot-target entries (BIOS, PXE, IDE-R, diagnostics, secure erase, codes 100–401) are informational. As in Console's MCP server, they need the separate boot-options flow and aren't accepted by `power_action`.

If rpc fails, the tool returns an MCP tool error (`isError: true`). The text contains the rpc exit code, the error that rpc logged, and a hint where one is known (for example "run the MCP server elevated").

### Power actions: important

Action codes and behavior are the same as Console's `power_action`:

| Action | Code | What rpc sends |
|---|---|---|
| `power_on` | 2 | IPS `RequestOSPowerSavingStateChange(full power)` if the OS is in power saving, then CIM `RequestPowerStateChange(2)` |
| `sleep` / `hibernate` | 4 / 7 | CIM `RequestPowerStateChange` |
| `power_cycle` | 5 | CIM `RequestPowerStateChange` |
| `power_off` / `power_off_soft` / `soft_off` | 8 / 9 / 12 | CIM `RequestPowerStateChange` |
| `reset` / `soft_reset` | 10 / 14 | CIM `RequestPowerStateChange` |
| `os_to_full_power` / `os_to_power_saving` | 500 / 501 | IPS `RequestOSPowerSavingStateChange` only (no-op if already in that state) |

Like Console, rpc doesn't pre-check the current power state. AMT itself rejects a transition it can't make (for example `ReturnValue` 4097, invalid state transition), and rpc reports that as a `WSMANMessageError`.

The MCP server runs on the device it controls. Every action except `power_on` and `os_to_full_power` stops, restarts or suspends the machine running the agent session, so **the session ends**. AMT acknowledges the request before acting, so the tool result is still returned first. The tool description tells the agent to call `power_get_capabilities` first and ask the user for explicit approval. The server refuses to run any action unless `confirm` is `true`.

Run with `--read-only` (or `RPC_MCP_READ_ONLY=true`) to remove `power_action` entirely.

## Prerequisites

- **rpc binary** built from this repo, version with the `power` command (`rpc power --help`). Build it with `go build -o rpc ./cmd/rpc` (or `rpc.exe` on Windows).
- **Administrator / root.** rpc talks to the Intel MEI/HECI driver, which needs elevation. Without it, `get_device_info` returns OS-level data only and the other tools fail with `IncorrectPermissions`. See [Running elevated](#running-elevated).
- **AMT activated** (CCM or ACM) for the power tools and `wsman_get`. Console isn't required: you can activate locally with `rpc activate --local --ccm --password <pw>`.
- **AMT admin password** in the `AMT_PASSWORD` environment variable of the rpc-mcp process, for the tools that need it.
- Go 1.25+ to build rpc-mcp.

## Build

rpc-mcp is a separate Go module (`./mcp/go.mod`). The root rpc module, its `go build ./...` / `go test ./...`, and its release scripts are not affected. For versioned Windows and Linux x64 builds into `dist/`, see [Getting started, section 2](docs/GETTING_STARTED.md#2-build).

```sh
# from the rpc-go repo root
make mcp                                # -> ./rpc-mcp
# or
cd mcp && go build -o rpc-mcp .         # Linux
cd mcp && go build -o rpc-mcp.exe .     # Windows

cd mcp && go test ./...                 # unit tests (no AMT hardware needed)
```

## Configuration

| Flag | Environment variable | Default | Purpose |
|---|---|---|---|
| `--rpc-path` | `RPC_PATH` | `rpc` on `PATH` | Path to the rpc binary. |
| `--devices-url` | `RPC_MCP_DEVICES_URL` | *(unset)* | Console devices API (e.g. `https://console.example.com/api/v1/devices`). Enables `register_device`. |
| `--read-only` | `RPC_MCP_READ_ONLY=true` | `false` | Do not expose `power_action`. |
| `--http` | | *(stdio)* | Serve MCP over HTTP on a **loopback** address, e.g. `127.0.0.1:8090`: streamable HTTP at `/` and legacy SSE at `/sse`. Non-loopback addresses are rejected because the endpoints have no authentication. |

rpc inherits rpc-mcp's environment, so the usual rpc variables apply:

| Variable | Used for |
|---|---|
| `AMT_PASSWORD` | AMT admin password (power, wsman, user certs). Passed through the environment, never on the command line. |
| `AUTH_TOKEN`, or `AUTH_USERNAME` + `AUTH_PASSWORD`, and `AUTH_ENDPOINT` | Console authentication for `register_device`. |
| `RPC_SKIP_CERT_CHECK=true` | Skip Console TLS verification (testing only). |
| `RPC_SKIP_AMT_CERT_CHECK=true` | Skip AMT/LMS TLS verification when TLS is enforced on local ports. |

rpc also reads `config.yaml` from its working directory (the directory rpc-mcp was started from). Keep stray config files out of that directory.

## Connecting to an AI agent

Ready-to-copy templates for every client are in [examples/](examples/), and the step-by-step setup is in [Getting started, section 6](docs/GETTING_STARTED.md#6-connect-an-ai-agent):

| Template | Client |
|---|---|
| `mcp.json`, `mcp-http.json`, `mcp-sse.json` | Claude Code and GitHub Copilot CLI: project `.mcp.json` (stdio / HTTP / SSE) |
| `copilot-cli-mcp-config.json` | GitHub Copilot CLI: `~/.copilot/mcp-config.json` |
| `vscode-mcp.json`, `vscode-mcp-http.json`, `vscode-mcp-sse.json` | VS Code + Copilot agent mode: `.vscode/mcp.json` (stdio / HTTP / SSE) |
| `claude_desktop_config.json` | Claude Desktop |

Replace the paths below with your own. On Windows, use `C:\\path\\to\\rpc-mcp.exe` in JSON files.

### Claude Code

```sh
claude mcp add rpc \
  -e AMT_PASSWORD='<amt-password>' \
  -e RPC_MCP_DEVICES_URL='https://console.example.com/api/v1/devices' \
  -e AUTH_TOKEN='<console-token>' \
  -- /opt/rpc/rpc-mcp --rpc-path /opt/rpc/rpc
```

Check it with `claude mcp list`, or `/mcp` inside a session. Then ask, for example, *"What is the AMT control mode and IP address of this device?"* or *"Show the power state of this device."*

### Claude Desktop (and other `mcpServers` JSON clients such as Cursor)

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "rpc": {
      "command": "/opt/rpc/rpc-mcp",
      "args": ["--rpc-path", "/opt/rpc/rpc"],
      "env": {
        "AMT_PASSWORD": "<amt-password>",
        "RPC_MCP_DEVICES_URL": "https://console.example.com/api/v1/devices",
        "AUTH_TOKEN": "<console-token>"
      }
    }
  }
}
```

### VS Code (GitHub Copilot agent mode)

`.vscode/mcp.json`. The `inputs` block prompts for the password instead of storing it:

```json
{
  "inputs": [
    { "id": "amtPassword", "type": "promptString", "description": "AMT admin password", "password": true }
  ],
  "servers": {
    "rpc": {
      "type": "stdio",
      "command": "/opt/rpc/rpc-mcp",
      "args": ["--rpc-path", "/opt/rpc/rpc"],
      "env": { "AMT_PASSWORD": "${input:amtPassword}" }
    }
  }
}
```

### Local HTTP mode

Use this when the MCP client can't be started elevated. Run rpc-mcp elevated (as root, or as a Windows service / elevated shell) and connect the client over HTTP on localhost:

```sh
sudo AMT_PASSWORD='<amt-password>' /opt/rpc/rpc-mcp --rpc-path /opt/rpc/rpc --http 127.0.0.1:8090
claude mcp add --transport http rpc http://127.0.0.1:8090
```

```json
{ "servers": { "rpc": { "type": "http", "url": "http://127.0.0.1:8090" } } }
```

For agents that only support the legacy **SSE** transport, use `http://127.0.0.1:8090/sse` on the same listener (`claude mcp add --transport sse rpc http://127.0.0.1:8090/sse`, or `"type": "sse"`). The handshake details are in [Getting started, section 5.3](docs/GETTING_STARTED.md#53-legacy-sse-endpoint-sse).

### MCP Inspector (manual testing)

```sh
npx @modelcontextprotocol/inspector /opt/rpc/rpc-mcp --rpc-path /opt/rpc/rpc
```

## Running elevated

- **Linux:** start the MCP client as root, or wrap the command with `sudo` (for example `"command": "sudo", "args": ["-E", "/opt/rpc/rpc-mcp", ...]` with a `NOPASSWD` sudoers rule limited to rpc-mcp), or use [local HTTP mode](#local-http-mode) with rpc-mcp running as root.
- **Windows:** start the MCP client (VS Code, Claude Desktop, terminal running Claude Code) "as Administrator", or use local HTTP mode with rpc-mcp started from an elevated shell or as a service.

rpc-mcp never prompts: rpc runs without stdin, so a missing password or elevation shows up as a tool error instead of a hung call.

## Security notes

- The agent can't choose where device data is sent. The Console URL for `register_device` comes only from server configuration.
- Secrets (AMT password, Console credentials) are passed through the environment and never appear in rpc's command line or in tool inputs. Prefer client features that prompt for secrets (VS Code `inputs`) over storing them in plain-text config files.
- `power_action` is marked `destructiveHint: true`, so well-behaved clients ask for approval. The server also enforces `confirm: true`. Use `--read-only` where power control isn't wanted.
- HTTP mode (both `/` and `/sse`) only binds to loopback and has no authentication: anything on the device that can reach the port can call the tools. The SDK's DNS-rebinding protection rejects requests whose `Host` header isn't localhost.

## Troubleshooting

| Tool error contains | Meaning / fix |
|---|---|
| `IncorrectPermissions` (code 1) | rpc isn't elevated. See [Running elevated](#running-elevated). |
| `HECIDriverNotDetected` (2) / `AmtNotDetected` (3) | No Intel MEI driver or AMT on this machine. |
| `MissingOrIncorrectPassword` (23) / `AMTAuthenticationFailed` (100) | Set or correct `AMT_PASSWORD`. |
| `DeviceNotActivated` (115) | Activate AMT first (`rpc activate ...`). Power and WSMAN tools need CCM or ACM. |
| `WSMANMessageError` (101) from `power_action` with `InvalidStateTransition (4097)` | AMT can't make that transition from the current state (for example `sleep` while the OS is already sleeping). Check `power_get_state` and `power_get_capabilities`. |
| `WSMANMessageError` (101) | AMT rejected the WSMAN request. Check the detail text, then rerun `rpc <command> --log-level debug` by hand. |
| `rpc binary not found` at startup | Set `--rpc-path` or `RPC_PATH`. |
| `... timed out after ...` | HECI or LMS busy. `amtinfo` retries for up to ~16s, so try again. |

rpc can exit with code 10 (GenericFailure) even when the real cause is a typed error. rpc-mcp reads the `Error <code>:` prefix of the logged message to pick the right hint.

## Adding a tool

1. Make sure rpc offers the operation as a command with `--json` output (add one under `internal/commands/` if needed. See the repo's `CLAUDE.md`).
2. Add the tool in [tools.go](tools.go) with `mcp.AddTool`: a typed input struct with `jsonschema` tags, the right `ToolAnnotations` (read-only, destructive), and a call to `runner.Run(ctx, timeout, "<command>", ...)`.
3. Add a test in [tools_test.go](tools_test.go) using the `fakeRPC` runner. Tests never start the real rpc.
