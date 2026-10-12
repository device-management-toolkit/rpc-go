---
name: rpc-mcp-operation
description: Operate the rpc-mcp server end to end on an Intel AMT device, from startup to sending tool calls. Use when the user wants to start/run rpc-mcp, connect to it, or perform an AMT action by plain request ("get device info", "what power state", "reset the device", "read AMT_GeneralSettings", "register the device") without writing the full MCP/JSON-RPC command themselves. Maps natural-language requests to the correct rpc-mcp tool call, including the build/activate prerequisites and troubleshooting by exit code.
---

# rpc-mcp operation skill

Turn a plain user request into the right rpc-mcp tool call. rpc-mcp runs **on the AMT device**, exposes a small set of tools over stdio or loopback HTTP, and each tool runs `rpc <command> --json` as a subprocess. This skill covers: getting the server up, sending a call, and the tool knowledge so the user can just say what they want.

When the user gives a plain request, do this:
1. Make sure the server is running (section 2). If not, start it (section 1).
2. Map the request to a tool (section 3 table).
3. Send the JSON-RPC `tools/call` using the helper (section 2).
4. If it errors, resolve by exit code (section 5).

Default endpoint used throughout: `http://127.0.0.1:8090/`. Default rpc binary: `./rpc`. Default AMT password in examples: `P@ssw0rd` (replace with the real one; always pass it via `AMT_PASSWORD`, never on argv).

## 1. Startup (prerequisites → running server)

Run these from the repo root (`/home/user/rpc-go`). Steps 1–2 are one-time per machine; step 4 is one-time per device; step 5 is what you repeat.

| # | Step | Command | Root? |
|---|---|---|---|
| 1 | Ensure Go 1.27+ is on PATH | `go version` (install to `~/.local/go-sdk` if missing) | no |
| 2 | Build both binaries | `go build -o rpc ./cmd/rpc && (cd mcp && go build -o ../rpc-mcp .)` | no |
| 3 | Confirm AMT is reachable | `sudo ./rpc amtinfo --ver --mode --uuid --json` | yes |
| 4 | Activate AMT if `controlMode` is `not activated` | `sudo ./rpc activate --local --ccm --password '<pw>'` | yes |
| 5 | Start the MCP server (leave running) | `sudo AMT_PASSWORD='<pw>' ./rpc-mcp --rpc-path ./rpc --http 127.0.0.1:8090` | yes |

Notes:
- The server **must run elevated** (HECI/MEI needs root). Password-protected tools read `AMT_PASSWORD` from the server's environment.
- `get_device_info` and `get_rpc_version` work without activation and without the password. All `power_*` and `wsman_get` need the device **activated** (CCM or ACM) and `AMT_PASSWORD` set.
- Activation (step 4) is a firmware state change — only do it when the user asks or `controlMode` is `not activated`. CCM is fully local (no provisioning cert). ACM requires a provisioning cert.
- Server flags: `--read-only` (or `RPC_MCP_READ_ONLY=true`) removes `power_action`; `--devices-url <url>` (or `RPC_MCP_DEVICES_URL`) enables `register_device`. `--http` must be a loopback address; omit `--http` for stdio transport.

## 2. Send a command over HTTP

MCP requires `initialize` → `notifications/initialized` → then any `tools/call`. Every call after `initialize` must carry the `Mcp-Session-Id` header. Set up the session once per shell:

```bash
U=http://127.0.0.1:8090/
H=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")

# initialize + capture the session id
SID=$(curl -s -D - -o /dev/null "${H[@]}" -X POST $U \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"skill","version":"1"}}}' \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')

send() { curl -s "${H[@]}" -H "Mcp-Session-Id: $SID" -X POST $U -d "$1"; echo; }
send '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
```

Then each action is one line (replace the `params`):

```bash
send '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"<TOOL>","arguments":<ARGS>}}'
```

To list the tools the server currently exposes: `send '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'`.

Replies come back as `event: message` then `data: {…}`. The tool result is in `result.structuredContent` (and duplicated as text). `"isError":true` means the tool failed — read the text and go to section 5.

## 3. Request → tool mapping (the knowledge)

When the user says any of these, call the matching tool. Build the `send '...'` line from the template above.

| User says (examples) | Tool | `arguments` | Needs pw / activation |
|---|---|---|---|
| "get device info", "show AMT info", "what's the control mode / UUID / version", "is it activated" | `get_device_info` | `{}` for all, or `{"fields":["version","controlMode","uuid"]}` for a subset | no |
| "rpc version", "which rpc build" | `get_rpc_version` | `{}` | no |
| "power state", "is it on", "is it asleep" | `power_get_state` | `{}` | yes |
| "what power actions are supported", "capabilities" | `power_get_capabilities` | `{}` | yes |
| "read AMT_GeneralSettings", "dump a WSMAN class", "diagnostics" | `wsman_get` | `{"classes":["AMT_GeneralSettings"]}` | yes |
| "register this device with Console", "sync inventory" | `register_device` *(only if `--devices-url` configured)* | `{}` | no |
| "reset", "power off", "power on", "reboot", "sleep", "hibernate", "power cycle" | `power_action` *(only if not `--read-only`)* | `{"action":"<name>","confirm":true}` | yes |

### get_device_info fields

`version, build, sku, uuid, upid, controlMode, provisioningState, dnsSuffix, hostname, lan, remoteAccess, operationalState, certificateHashes, userCertificates, proxy`. Omit `fields` to return everything. `userCertificates` and `proxy` additionally need the AMT password.

### power_action names

`power_on, power_off, power_off_soft, soft_off, reset, soft_reset, power_cycle, sleep, hibernate, os_to_full_power, os_to_power_saving`.

**Destructive-action rule:** `power_action` requires `"confirm": true`, and the server rejects it otherwise. Because the server runs on the device it controls, every action except `power_on` and `os_to_full_power` **stops, reboots or suspends this machine and ends the session**. Before sending a destructive action: call `power_get_capabilities`, tell the user exactly what will happen, and get explicit approval. Only then send with `confirm: true`.

## 4. Ready-to-send examples

```bash
# Device info (everything)
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_device_info","arguments":{}}}'

# Just control mode + uuid + version
send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_device_info","arguments":{"fields":["controlMode","uuid","version"]}}}'

# Power state  -> {"powerState":2,"osPowerSavingState":2}
send '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"power_get_state","arguments":{}}}'

# Supported power actions
send '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"power_get_capabilities","arguments":{}}}'

# Read a WSMAN class
send '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"wsman_get","arguments":{"classes":["AMT_GeneralSettings"]}}}'

# DESTRUCTIVE: reset the device (only after explicit user approval)
send '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"power_action","arguments":{"action":"reset","confirm":true}}}'
```

Output reference:
- `powerState` (CIM): 2 on, 3/4 sleep, 6/8 off, 7 hibernate.
- `osPowerSavingState`: 0 unknown, 1 unsupported, 2 full power, 3 OS power saving.

## 5. Troubleshooting by exit code

A failed tool returns `"isError":true` and text like `rpc exited with code <N>: ... (hint: ...)`. Prefer the `Error <N>:` code embedded in the message. Resolutions:

| Code | Meaning | Fix |
|---|---|---|
| 1 | Needs admin/root | Restart the server with `sudo` |
| 2 | MEI/HECI driver not detected | Confirm `/dev/mei0` exists and the AMT driver is loaded |
| 3 | AMT not detected | Not an AMT device, or AMT disabled in BIOS |
| 23 / 100 | AMT password missing/incorrect | Set the correct `AMT_PASSWORD` on the server and restart |
| 115 | AMT not activated | Activate first: `sudo ./rpc activate --local --ccm --password '<pw>'` |

Other checks:
- `heciAvailable:false` in `get_device_info` → server is not elevated (or no MEI driver). Restart with `sudo`.
- Connection refused → the server isn't running; redo section 1 step 5.
- Verify the live device state any time with `sudo AMT_PASSWORD='<pw>' ./rpc amtinfo --mode --json`.

## Related

- Tool definitions and gating: [mcp/tools.go](../../../mcp/tools.go). Exit-code hints: [mcp/runner.go](../../../mcp/runner.go).
- Manual testing (stdio, streamable HTTP, legacy SSE): [mcp/docs/MANUAL_TESTING.md](../../../mcp/docs/MANUAL_TESTING.md).
- Capabilities, config and agent hookup: [mcp/README.md](../../../mcp/README.md).
- Design rules (when changing rpc-mcp, not operating it): [rpc-mcp-architecture skill](../rpc-mcp-architecture/SKILL.md).
