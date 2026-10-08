# Manual testing on the target device (no AI agent)

These are copy-paste commands to test rpc and rpc-mcp **by hand on the AMT device**, without an AI agent. Use them to accept a new build, or to tell apart "the agent is wrong" from "the server or device is wrong".

Build and deployment are covered in [GETTING_STARTED.md](GETTING_STARTED.md), and the design in [ARCHITECTURE.md](ARCHITECTURE.md).

Test from the bottom up. If a lower layer fails, the layers above it can't pass.

| Layer | What it proves | Section |
|---|---|---|
| L1: rpc CLI | Device, elevation, activation and password are OK, and the rpc commands work | [§3](#3-l1-rpc-cli-no-mcp) |
| L2: streamable HTTP `/` | The endpoint Claude Code, VS Code and Copilot use | [§4](#4-l2-streamable-http-endpoint-) |
| L3: legacy SSE `/sse` | The endpoint SSE-only agents use | [§5](#5-l3-legacy-sse-endpoint-sse) |

## 1. Prerequisites

- `rpc` and `rpc-mcp` are deployed side by side, e.g. `C:\Program Files\rpc\` or `/opt/rpc/`.
- You have an **elevated** shell: PowerShell "Run as administrator" on Windows, `sudo` on Linux.
- AMT is **activated**: `rpc amtinfo --mode` shows "activated in …". If it isn't, activate locally with `rpc activate --local --ccm --password '<pw>'`.
- You know the AMT admin password.
- **Windows:** the commands below use PowerShell's `Invoke-WebRequest` for requests, and `curl.exe` (built into Windows 10+) only to hold the SSE stream open. In Windows PowerShell 5.1, plain `curl` is an alias for `Invoke-WebRequest`, so write `curl.exe` explicitly.

## 2. Start the server

Do this in shell 1, **elevated**, and leave it running:

```powershell
# Windows
$env:AMT_PASSWORD = '<amt-password>'
cd 'C:\Program Files\rpc'
.\rpc-mcp.exe --rpc-path .\rpc.exe --http 127.0.0.1:8090
# -> rpc-mcp listening on http://127.0.0.1:8090 (streamable HTTP) and http://127.0.0.1:8090/sse (legacy SSE)
```

```sh
# Linux
sudo AMT_PASSWORD='<amt-password>' /opt/rpc/rpc-mcp --rpc-path /opt/rpc/rpc --http 127.0.0.1:8090
```

Run the tests from **shell 2**, which doesn't need elevation.

## 3. L1: rpc CLI (no MCP)

Run in an elevated shell with `AMT_PASSWORD` set:

```sh
rpc version --json
rpc amtinfo --ver --mode --uuid --json      # must show an activated control mode
rpc power state --json                      # {"powerState":2,"osPowerSavingState":2}
rpc power capabilities --json               # supportedActions + capabilities
```

If these fail, fix the device first: elevation, MEI driver, activation, password.

## 4. L2: streamable HTTP endpoint (`/`)

Each request is a `POST /`. After `initialize`, every request must send the `Mcp-Session-Id` header that `initialize` returned. Replies come back as `event: message` followed by `data: {…}`.

### Windows PowerShell (shell 2)

```powershell
$U = 'http://127.0.0.1:8090/'
$H = @{ Accept = 'application/json, text/event-stream' }
function Send-Mcp($Body) { Invoke-WebRequest -UseBasicParsing -Method Post -Uri $U -Headers $H -ContentType 'application/json' -Body $Body }

# 1. initialize, then keep the session id for all later requests
$r = Send-Mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual","version":"1"}}}'
$r.Content                                   # serverInfo name = rpc-mcp
$H['Mcp-Session-Id'] = $r.Headers['Mcp-Session-Id']

# 2. initialized notification -> 202
(Send-Mcp '{"jsonrpc":"2.0","method":"notifications/initialized"}').StatusCode

# 3. list tools
(Send-Mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}').Content

# 4. call tools (see the test table in section 6)
(Send-Mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_rpc_version","arguments":{}}}').Content
(Send-Mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_device_info","arguments":{"fields":["version","controlMode","uuid"]}}}').Content
(Send-Mcp '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"power_get_state","arguments":{}}}').Content
(Send-Mcp '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"power_get_capabilities","arguments":{}}}').Content
(Send-Mcp '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"wsman_get","arguments":{"classes":["AMT_GeneralSettings"]}}}').Content
(Send-Mcp '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"power_action","arguments":{"action":"reset","confirm":false}}}').Content
(Send-Mcp '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"power_action","arguments":{"action":"explode","confirm":true}}}').Content

# 5. end the session -> 204
(Invoke-WebRequest -UseBasicParsing -Method Delete -Uri $U -Headers @{ 'Mcp-Session-Id' = $H['Mcp-Session-Id'] }).StatusCode
```

### Linux bash (shell 2)

```sh
U=http://127.0.0.1:8090/
H=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")

# 1. initialize -> copy the Mcp-Session-Id response header
curl -s -D - "${H[@]}" -X POST $U \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual","version":"1"}}}'
SID=<paste Mcp-Session-Id>
send() { curl -s "${H[@]}" -H "Mcp-Session-Id: $SID" -X POST $U -d "$1"; echo; }

# 2-4. notification, list, tool calls
send '{"jsonrpc":"2.0","method":"notifications/initialized"}'
send '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_rpc_version","arguments":{}}}'
send '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"power_get_state","arguments":{}}}'
send '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"power_action","arguments":{"action":"reset","confirm":false}}}'

# 5. end the session -> 204
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE -H "Mcp-Session-Id: $SID" $U
```

## 5. L3: legacy SSE endpoint (`/sse`)

This needs **two shells**. Shell A holds the event stream open, and every reply appears there. Shell B POSTs the requests, and each POST only returns `202`.

**Shell A: open the stream and leave it running.**

```powershell
curl.exe -N http://127.0.0.1:8090/sse          # Linux: curl -N http://127.0.0.1:8090/sse
# event: endpoint
# data: /sse?sessionid=GAPH452HYV6LOJ4MAJ534QJ6LZ    <- copy this session path
```

**Shell B: POST to that session URL.**

```powershell
# Windows PowerShell
$EP = 'http://127.0.0.1:8090/sse?sessionid=GAPH452HYV6LOJ4MAJ534QJ6LZ'   # <- paste yours
function Send-Sse($Body) { (Invoke-WebRequest -UseBasicParsing -Method Post -Uri $EP -ContentType 'application/json' -Body $Body).StatusCode }

Send-Sse '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"manual","version":"1"}}}'
Send-Sse '{"jsonrpc":"2.0","method":"notifications/initialized"}'
Send-Sse '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
Send-Sse '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"power_get_state","arguments":{}}}'
# each prints 202
```

```sh
# Linux bash
EP="http://127.0.0.1:8090/sse?sessionid=GAPH452HYV6LOJ4MAJ534QJ6LZ"   # <- paste yours
post() { curl -s -o /dev/null -w "POST %{http_code}\n" -X POST "$EP" -H "Content-Type: application/json" -d "$1"; }
post '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"manual","version":"1"}}}'
post '{"jsonrpc":"2.0","method":"notifications/initialized"}'
post '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"power_get_state","arguments":{}}}'
```

**Shell A then shows the replies.**

```
event: message
data: {"jsonrpc":"2.0","id":1,"result":{...,"serverInfo":{"name":"rpc-mcp","version":"0.1.0"}}}

event: message
data: {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"powerState\":2,\"osPowerSavingState\":2}"}],...}}
```

Press `Ctrl+C` in shell A to end the session.

**Security check (optional).** A foreign `Host` header must be refused:

```sh
curl.exe -s -o NUL -w "%{http_code}\n" -H "Host: attacker.example.com" http://127.0.0.1:8090/sse    # expect 403  (Linux: curl ... -o /dev/null)
```

## 6. Expected results

How to read a reply:
- `"result"` without `"isError":true` means the tool succeeded.
- `"isError":true` means the tool ran but failed; the `text` says why.
- `"error":{…}` is a protocol error, usually a missing or stale session id.

| ID | Request | Expected (activated device, elevated server, password set) |
|---|---|---|
| T0 | `initialize`, `tools/list` | `serverInfo.name` = `rpc-mcp`. Tools: `get_device_info get_rpc_version power_action power_get_capabilities power_get_state wsman_get` (plus `register_device` if `--devices-url` is set) |
| T1 | `get_rpc_version` | rpc version JSON |
| T2 | `get_device_info` `{"fields":["version","controlMode","uuid"]}` | `amt`, `controlMode`, `uuid` |
| T3 | `power_get_state` | `{"powerState":2,"osPowerSavingState":2}` |
| T4 | `power_get_capabilities` | `supportedActions` includes `power_cycle power_off power_on reset` (plus `sleep hibernate soft_off soft_reset` on AMT > 9) |
| T5 | `wsman_get` `{"classes":["AMT_GeneralSettings"]}` | AMT general settings JSON |
| T6 | `power_action` `{"action":"reset","confirm":false}` | `isError:true`, "power_action was not executed: set confirm=true …". **The device must not reset** |
| T7 | `power_action` `{"action":"explode","confirm":true}` | `isError:true`, "unsupported action …" |
| T8 *(destructive, run last)* | `power_action` `{"action":"reset","confirm":true}` | `{"action":"reset","code":10,"returnValue":0}`, then the device restarts |

What failures usually mean:
- **Not elevated:** T0–T2, T6 and T7 pass. T3–T5 return `IncorrectPermissions` with the hint "run the MCP server elevated".
- **Server started with `--read-only`:** `power_action` isn't listed.

**T8 (real power action).** Run it last, on the streamable session from §4:

```powershell
(Send-Mcp '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"power_action","arguments":{"action":"reset","confirm":true}}}').Content
```

The reply arrives first, then the machine restarts. After the reboot, start the server again and rerun T3. Actions that power the device off (`power_off`, `soft_off`, …) need a power-button press or a remote power-on to bring it back.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Connection refused | The server isn't running with `--http`, or is on a different port |
| `--http must bind to a loopback address` | Use `127.0.0.1`, `::1` or `localhost` |
| `"method … is invalid during session initialization"` | Missing or stale `Mcp-Session-Id`. Run `initialize` again |
| SSE POST returns `404`/`400` | Wrong session URL, or shell A's stream was closed. Reopen `GET /sse` |
| `403 Forbidden` | Non-localhost `Host` header (DNS-rebinding protection) |
| `IncorrectPermissions` | The server shell isn't elevated |
| `DeviceNotActivated` | `rpc activate --local --ccm --password '<pw>'` |
| `AMTAuthenticationFailed` / `MissingOrIncorrectPassword` | `AMT_PASSWORD` is wrong or not set in the **server's** shell |
| A tool times out | HECI or LMS busy. Check `rpc amtinfo` directly (§3) |

More error codes are listed in the [README troubleshooting table](../README.md#troubleshooting).
