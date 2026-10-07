# Getting started: build, run and connect an AI agent

This guide takes you from source to an AI agent (Claude Code, GitHub Copilot, Claude Desktop) that can read Intel AMT information and run power actions on a device through **rpc** and **rpc-mcp**.

- What the tools do: [README](../README.md#capabilities)
- Why it is designed this way: [ARCHITECTURE.md](ARCHITECTURE.md)

Commands are shown for **bash** (Linux, macOS, Git Bash) and **PowerShell** (Windows). In PowerShell, chain commands with `;`, not `&&`.

## 1. Prerequisites

| Where | Needed |
|---|---|
| Build machine | Go **1.27+** (rpc requires it; rpc-mcp alone needs 1.25+), git |
| Target device | Intel AMT (vPro), the Intel MEI driver, optionally the Intel LMS service, and **administrator/root** rights |
| Power, WSMAN and user-certificate tools | AMT **activated** (CCM or ACM) and the AMT admin password |
| Optional | Node.js 18+ for MCP Inspector; a Console server for device registration |

## 2. Build

rpc-go contains two independent Go modules:

| Module | Directory | Binary |
|---|---|---|
| rpc (CLI) | repo root | `rpc` / `rpc.exe` |
| rpc-mcp (MCP server) | `mcp/` | `rpc-mcp` / `rpc-mcp.exe` |

### 2.1 Quick native build (for this machine)

```sh
# bash, from the rpc-go repo root
go build -o rpc ./cmd/rpc
(cd mcp && go build -o ../rpc-mcp .)
```

```powershell
# PowerShell, from the rpc-go repo root
go build -o rpc.exe ./cmd/rpc
Push-Location mcp; go build -o ..\rpc-mcp.exe .; Pop-Location
```

With `make` installed, `make build` builds rpc and `make mcp` builds `./rpc-mcp`.

### 2.2 Release-style build for Windows and Linux x64

This build injects the version (the same ldflags as `build.sh`) and writes the binaries to `dist/`, which git ignores:

```sh
# bash (also works in Git Bash on Windows)
VERSION=$(git describe --tags --always 2>/dev/null || echo dev)
DATE=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
PKG=github.com/device-management-toolkit/rpc-go/v2/pkg/utils
LDF="-s -w -X '$PKG.ProjectVersion=$VERSION' -X '$PKG.BuildDate=$DATE' -X '$PKG.BuildCommit=$COMMIT'"

for os in windows linux; do
  ext=""; [ "$os" = windows ] && ext=".exe"
  out=dist/${os}_amd64; mkdir -p "$out"
  CGO_ENABLED=0 GOOS=$os GOARCH=amd64 go build -trimpath -ldflags "$LDF" -o "$out/rpc$ext" ./cmd/rpc
  (cd mcp && CGO_ENABLED=0 GOOS=$os GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "../$out/rpc-mcp$ext" .)
done
```

```powershell
# PowerShell
$VERSION = (git describe --tags --always 2>$null); if (-not $VERSION) { $VERSION = "dev" }
$DATE    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$COMMIT  = (git rev-parse --short HEAD 2>$null); if (-not $COMMIT) { $COMMIT = "unknown" }
$PKG     = "github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
$LDF     = "-s -w -X '$PKG.ProjectVersion=$VERSION' -X '$PKG.BuildDate=$DATE' -X '$PKG.BuildCommit=$COMMIT'"

$env:CGO_ENABLED = "0"; $env:GOARCH = "amd64"
foreach ($os in "windows", "linux") {
  $ext = if ($os -eq "windows") { ".exe" } else { "" }
  $out = "dist\${os}_amd64"; New-Item -ItemType Directory -Force $out | Out-Null
  $env:GOOS = $os
  go build -trimpath -ldflags $LDF -o "$out\rpc$ext" ./cmd/rpc
  Push-Location mcp; go build -trimpath -ldflags "-s -w" -o "..\$out\rpc-mcp$ext" .; Pop-Location
}
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
```

Result (both are static binaries with no runtime dependencies):

```
dist/
├── windows_amd64/  rpc.exe  rpc-mcp.exe
└── linux_amd64/    rpc      rpc-mcp
```

### 2.3 Test and check the build

```sh
go test ./internal/commands/ ./internal/cli/     # rpc (root module)
(cd mcp && go test ./...)                        # rpc-mcp

dist/windows_amd64/rpc.exe version --json        # shows the injected version
dist/windows_amd64/rpc.exe power --help          # the power command is present
dist/windows_amd64/rpc-mcp.exe --help            # rpc-mcp flags
```

## 3. Deploy to the device

Copy **both** binaries into the same directory on the AMT device:

| OS | Suggested location | Notes |
|---|---|---|
| Windows | `C:\Program Files\rpc\` | The config templates in `mcp/examples/` use this path |
| Linux | `/opt/rpc/` | `sudo chmod +x /opt/rpc/rpc /opt/rpc/rpc-mcp` |

rpc reads an optional `config.yaml` from its **working directory** as flag defaults. Keep stray `config.yaml` files out of the directory that rpc-mcp (and so rpc) is started from.

## 4. Run rpc (CLI)

Run these in an **elevated** shell (Windows: "Run as administrator"; Linux: `sudo`). Every command accepts `--json` for machine-readable output.

```sh
rpc version --json                     # rpc version
rpc amtinfo                            # AMT and OS information (works unelevated, OS data only)
rpc amtinfo --ver --mode --lan --json  # selected fields

# Power (AMT must be activated; password from --password or AMT_PASSWORD)
export AMT_PASSWORD='<amt-password>'   # PowerShell: $env:AMT_PASSWORD = '<amt-password>'
rpc power state --json                 # current state + availableActions
rpc power action --state reset --json  # !! restarts this machine

# Discovery: register / sync this device with Console
rpc amtinfo --discover --url https://console.example.com/api/v1/devices --auth-token '<token>' --json
```

Actions for `rpc power action --state`: `off`, `soft-off`, `reset`, `graceful-reset`, `cycle`, `sleep`, `hibernate`, `nmi`. AMT accepts only the actions listed in `power state`'s `availableActions`.

## 5. Run rpc-mcp

You rarely start rpc-mcp by hand in stdio mode. The AI agent launches it (section 6). Its settings:

| Flag | Env var | Default | Purpose |
|---|---|---|---|
| `--rpc-path` | `RPC_PATH` | `rpc` on PATH | Path to the rpc binary |
| `--devices-url` | `RPC_MCP_DEVICES_URL` | unset | Console devices API; enables the `register_device` tool |
| `--read-only` | `RPC_MCP_READ_ONLY=true` | false | Hide the `power_action` tool |
| `--http` | | stdio | Serve streamable HTTP on a loopback address, e.g. `127.0.0.1:8090` |

rpc inherits rpc-mcp's environment: `AMT_PASSWORD`, plus `AUTH_TOKEN` or `AUTH_USERNAME`/`AUTH_PASSWORD` for Console.

### 5.1 stdio mode (default)

The agent starts `rpc-mcp --rpc-path <rpc>` and talks MCP over stdin/stdout. rpc runs only as elevated as the agent is, so **start the agent elevated** if you need AMT access.

### 5.2 Local HTTP mode (elevated server, unelevated agent)

Run rpc-mcp elevated once, and point any agent at `http://127.0.0.1:8090`. Only loopback addresses are accepted, because the endpoint has no authentication.

```powershell
# Windows: elevated PowerShell ("Run as administrator")
$env:AMT_PASSWORD = '<amt-password>'
& 'C:\Program Files\rpc\rpc-mcp.exe' --rpc-path 'C:\Program Files\rpc\rpc.exe' --http 127.0.0.1:8090
# Ctrl+C to stop
```

```sh
# Linux, ad hoc
sudo AMT_PASSWORD='<amt-password>' /opt/rpc/rpc-mcp --rpc-path /opt/rpc/rpc --http 127.0.0.1:8090
```

On Linux, run it as a systemd service, with the password in a root-only file:

```ini
# /etc/systemd/system/rpc-mcp.service
[Unit]
Description=rpc-mcp (Intel AMT MCP server)
After=network.target

[Service]
WorkingDirectory=/opt/rpc
EnvironmentFile=/etc/rpc-mcp.env
ExecStart=/opt/rpc/rpc-mcp --rpc-path /opt/rpc/rpc --http 127.0.0.1:8090
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
echo "AMT_PASSWORD=<amt-password>" | sudo tee /etc/rpc-mcp.env >/dev/null && sudo chmod 600 /etc/rpc-mcp.env
sudo systemctl daemon-reload && sudo systemctl enable --now rpc-mcp
```

Quick check that the server answers:

```sh
curl -s -X POST http://127.0.0.1:8090 -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
# -> data: {... "serverInfo":{"name":"rpc-mcp", ...}}
```

## 6. Connect an AI agent

Ready-made config files are in [`mcp/examples/`](../examples/). They use the Windows paths from section 3; on Linux, replace them with `/opt/rpc/rpc-mcp` and `/opt/rpc/rpc`.

| Agent | Template | Copy to |
|---|---|---|
| Claude Code and GitHub Copilot CLI (project) | [`mcp.json`](../examples/mcp.json) (stdio) / [`mcp-http.json`](../examples/mcp-http.json) | `<project>/.mcp.json` |
| GitHub Copilot CLI (user) | [`copilot-cli-mcp-config.json`](../examples/copilot-cli-mcp-config.json) | `~/.copilot/mcp-config.json` |
| VS Code + GitHub Copilot agent mode | [`vscode-mcp.json`](../examples/vscode-mcp.json) (stdio) / [`vscode-mcp-http.json`](../examples/vscode-mcp-http.json) | `<workspace>/.vscode/mcp.json` |
| Claude Desktop | [`claude_desktop_config.json`](../examples/claude_desktop_config.json) | Windows `%APPDATA%\Claude\claude_desktop_config.json`, macOS `~/Library/Application Support/Claude/claude_desktop_config.json` |

The templates contain **no secrets**:
- The `.mcp.json` files expand `${AMT_PASSWORD}`, `${RPC_MCP_DEVICES_URL}` and `${RPC_CONSOLE_TOKEN}` from your environment.
- VS Code prompts for the password.
- Claude Desktop has no variable expansion, so you have to fill in `<amt-password>` yourself. Keep that file private.

### 6.1 Claude Code

```sh
# Option A: CLI, stored for you only (user scope = all projects)
claude mcp add rpc --scope user --transport stdio \
  -e AMT_PASSWORD='<amt-password>' \
  -- "C:\Program Files\rpc\rpc-mcp.exe" --rpc-path "C:\Program Files\rpc\rpc.exe"

# Option B: project file, shared with the team (secrets come from env vars)
cp mcp/examples/mcp.json <project>/.mcp.json

# Option C: local HTTP mode (section 5.2)
claude mcp add --transport http rpc http://127.0.0.1:8090
```

Check it with `claude mcp list`, or with `/mcp` inside a session. Claude Code asks you to approve project `.mcp.json` servers the first time.

### 6.2 VS Code with GitHub Copilot (agent mode)

1. Copy `mcp/examples/vscode-mcp.json` to `.vscode/mcp.json` in your workspace and adjust the paths. Alternatively, run **MCP: Add Server…** from the Command Palette.
2. Open `.vscode/mcp.json` and click **Start** above the `rpc` server, or run **MCP: List Servers → rpc → Start**. Enter the AMT password when prompted.
3. Open Copilot Chat, switch to **Agent** mode, click the **tools** icon, and make sure the `rpc` tools are enabled.
4. Copilot asks for confirmation before running a tool. Read the `power_action` request before approving it.

For local HTTP mode, use `vscode-mcp-http.json` instead. VS Code itself only needs to run elevated in stdio mode.

### 6.3 GitHub Copilot CLI

```sh
# user config (~/.copilot/mcp-config.json)
copilot mcp add rpc --env AMT_PASSWORD='<amt-password>' \
  -- "C:\Program Files\rpc\rpc-mcp.exe" --rpc-path "C:\Program Files\rpc\rpc.exe"

copilot mcp list          # verify
# inside a session: /mcp show rpc
```

Copilot CLI also reads a project `.mcp.json` (or `.github/mcp.json`), so the Claude Code template from 6.1 option B works for both. It does **not** read `.vscode/mcp.json`.

### 6.4 Claude Desktop

Merge `mcp/examples/claude_desktop_config.json` into your `claude_desktop_config.json` (Settings → Developer → Edit Config), set the password, and restart Claude Desktop. To get AMT access, start Claude Desktop **as administrator**, or use local HTTP mode via a client that supports HTTP servers.

### 6.5 MCP Inspector (manual testing without an agent)

```sh
npx @modelcontextprotocol/inspector "C:\Program Files\rpc\rpc-mcp.exe" --rpc-path "C:\Program Files\rpc\rpc.exe"
```

In the Inspector UI: **Connect → Tools → List Tools**, then call `get_rpc_version` and `get_device_info`.

## 7. Use it from the agent

Example prompts:

| Prompt | Tool(s) the agent uses |
|---|---|
| "What version of AMT is on this device, and is it activated?" | `get_device_info` (`version`, `controlMode`) |
| "Show the IP and MAC address of the AMT wired interface." | `get_device_info` (`lan`) |
| "What is the current power state? Which power actions are allowed?" | `get_power_state` |
| "Register this device with Console." | `register_device` (only when `--devices-url` is set) |
| "Read AMT_GeneralSettings." | `wsman_get` |
| "Restart this machine through AMT." | `get_power_state`, then asks you, then `power_action` with `confirm: true` |

**Power actions run on the machine the agent is on.** A reset or power-off ends the agent session. The agent is told to ask you first, and rpc-mcp refuses to act without `confirm: true`. To remove the tool entirely, start rpc-mcp with `--read-only` (or add `"RPC_MCP_READ_ONLY": "true"` to the template's `env`).

## 8. Checklist and troubleshooting

1. `rpc version --json` works on the device, and `rpc power --help` lists `state` and `action`.
2. `rpc amtinfo --mode` (elevated) shows the control mode; it must be activated for power and WSMAN.
3. The agent lists the rpc tools: `claude mcp list`, VS Code **MCP: List Servers**, `copilot mcp list`, or Inspector.
4. `get_rpc_version` succeeds from the agent, which proves the agent → rpc-mcp → rpc path works.
5. `get_power_state` succeeds, which proves elevation and `AMT_PASSWORD` are correct.

For error messages (`IncorrectPermissions`, `DeviceNotActivated`, `AMTAuthenticationFailed`, …), see the [README troubleshooting table](../README.md#troubleshooting).
