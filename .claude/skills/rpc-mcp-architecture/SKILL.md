---
name: rpc-mcp-architecture
description: Architecture, design rules and implementation recipes for rpc-mcp, the MCP server in rpc-go/mcp that exposes the rpc CLI (Intel AMT device info, discovery/registration, power actions) to AI agents. Use when designing or implementing enhancements to rpc-mcp or to the rpc commands it calls, such as adding or changing an MCP tool, adding an rpc command for a new tool, changing transport/safety/error handling, extending power or discovery features, reviewing an rpc-mcp change, or updating its architecture docs and diagrams.
---

# rpc-mcp architecture skill

rpc-mcp is a Go MCP server that runs **on the AMT device** and turns MCP tool calls into `rpc <command> --json` subprocess runs. Use this skill whenever you change rpc-mcp or the rpc commands it depends on. It keeps changes consistent with the recorded design.

**Read first, every time:**
1. [mcp/docs/ARCHITECTURE.md](../../../mcp/docs/ARCHITECTURE.md): decisions D1–D8 and the diagrams. It is the source of truth for the design.
2. [CLAUDE.md](../../../CLAUDE.md): the rpc-go rules. They still apply to any change under `internal/` or `pkg/`.
3. The current code in `mcp/` (`main.go`, `tools.go`, `runner.go`), which may have moved on since this skill was written.

## Design invariants (do not break without a recorded decision)

| # | Invariant | Why |
|---|---|---|
| D1 | rpc-mcp runs on the managed device and manages only that device. | rpc reaches AMT only locally (HECI/LMS at 127.0.0.1). |
| D2 | rpc-mcp **runs the rpc binary** (`exec`, `--json`). It never imports rpc-go packages. | `internal/` can't be imported. This also gives process isolation per call and typed exit codes, the same model as `internal/orchestrator`. |
| D3 | `mcp/` is a **nested Go module** with its own `go.mod`. The root `go.mod`, Dockerfile and release scripts must not depend on it. | Builds independently, so it can move to its own repository later. |
| D4 | rpc-go changes are **new self-contained commands** that follow the `AMTBaseCmd` → `EnsureAMTPassword` → `EnsureWSMAN` pattern and support `--json`. Don't change rpc-go's lifecycle, CLI architecture or other commands for MCP's sake. | Keeps the rpc-go diff small and its architecture unchanged. |
| D5 | **One tool maps to one rpc invocation.** Tool JSON output is rpc's `--json` stdout, unchanged. | The output stays predictable, and rpc can also be run by hand to reproduce. |
| D6 | **Safety:** no secrets in argv or tool input (use env vars). Outbound URLs are set on the server, never taken from tool input. Destructive tools carry `DestructiveHint` and a `confirm: true` gate, and are disabled by `--read-only`. HTTP mode is loopback-only. rpc runs with no stdin. | Guards against prompt injection and accidents. Power actions end the session on this host. |
| D7 | A non-zero rpc exit becomes an MCP **tool error** (`isError`) containing the exit code, the last `level=error` log message and a hint. Prefer the `Error <N>:` code in the message (rpc may exit with 10). | The agent can reason about the failure; protocol errors are reserved for real protocol faults. |
| D8 | Elevation is external. Either the client runs elevated (stdio) or rpc-mcp does (loopback HTTP). Never add self-elevation or password prompts. | HECI needs admin/root, and an MCP server must not block on a prompt. |

If an enhancement needs to break one of these, **stop and make it a design change** (workflow C) instead of slipping it into an implementation.

## Code map

| Path | Role |
|---|---|
| `mcp/main.go` | Flags and env (`--rpc-path`/`RPC_PATH`, `--devices-url`/`RPC_MCP_DEVICES_URL`, `--read-only`/`RPC_MCP_READ_ONLY`, `--http`), stdio vs loopback HTTP, loopback check |
| `mcp/tools.go` | `registerTools`: tool definitions, input structs (`jsonschema` tags), annotations, allow-lists, the `confirm` gate, timeouts, `result()` adapter |
| `mcp/runner.go` | `Runner.Run(ctx, timeout, args...)`: appends `--json`, inherits env, maps exit codes and stderr to `RPCError`, `exitCodeHints` |
| `mcp/*_test.go` | `fakeRPC` exec stub, plus in-memory MCP client/server tests (`connect`, `callTool`) |
| `mcp/README.md` | Developer guide: capabilities table, client hookup, config, troubleshooting |
| `mcp/docs/ARCHITECTURE.md` | Decisions D1–D8 and Mermaid diagrams |
| `mcp/docs/GETTING_STARTED.md` | Build (native and `dist/` Windows/Linux x64), deploy, run, agent hookup. Update it when flags, tools or build steps change |
| `mcp/examples/*.json` | Agent config templates: `.mcp.json` (Claude Code and Copilot CLI), VS Code `mcp.json`, Copilot CLI user config, Claude Desktop. Keep them in sync with the flags |
| `internal/commands/power.go` | `rpc power state` and `rpc power action` (example of a D4-style command) |
| `internal/interfaces/wsman.go`, `internal/local/amt/wsman.go` | `WSMANer` seam and adapter; add WSMAN calls here, then run `make mock` |
| `internal/cli/cli.go` | Register new top-level commands: a `CLI` field plus `knownCommands` |

## Workflows

### A. Add an MCP tool backed by an existing rpc command

1. Run `go run ./cmd/rpc/main.go <command> --help` and confirm the exact flag names (the `name:` tag wins) and that `--json` prints a JSON **object** on stdout.
2. Decide the tool's kind: read-only, writes externally, or destructive. Destructive needs `confirm` plus `--read-only` gating, and external writes need a server-configured target (D6).
3. Add it in `tools.go` with the template in [references/recipes.md](references/recipes.md#tool-template). Use enum allow-lists for any value that becomes an rpc argument, and never pass free-form tool input as a flag value without validating it.
4. Choose a timeout: anything that runs `AMTBaseCmd.AfterApply` can take ~16s or more because of HECI retries.
5. Add exit-code hints in `runner.go` if the command has new failure modes.
6. Add tests in `tools_test.go`: argument construction, gating, error mapping.
7. Update the README capabilities table and tool inputs, and the tool-to-command diagram (§3) and D5 table in ARCHITECTURE.md.

### B. Add a tool that needs a new rpc capability

Do this as **two PRs**: the rpc command first (`feat(internal): …`), then the MCP tool (workflow A).

1. Check that go-wsman-messages already has the message. If not, fix it upstream; never hand-write WSMAN XML (CLAUDE.md).
2. Add the `WSMANer` methods and their adapter, then run `make mock` (or `go run go.uber.org/mock/mockgen@v0.6.0 -source ./internal/interfaces/wsman.go -destination ./internal/mocks/wsman_mock.go -package=mock`).
3. Add the command under `internal/commands/` with the template in [references/recipes.md](references/recipes.md#rpc-command-template): embed `AMTBaseCmd`, check activation, `EnsureAMTPassword` then `EnsureWSMAN`, typed `utils.CustomError` failures, and a `--json` branch.
4. Register it in `internal/cli/cli.go` (a `CLI` field plus `knownCommands`).
5. Write gomock tests covering success, not activated, WSMAN error, bad firmware return value, and the JSON shape.

### C. Change the design

Examples: fleet/remote control through Console/MPS, auth on HTTP mode, a long-running rpc mode, resources or prompts, or a new outbound integration.

1. Write the proposal as a new decision `D9…` in ARCHITECTURE.md. Cover context, decision, alternatives and consequences, and update the invariant it supersedes.
2. Update or add the Mermaid diagrams that change (context §1, components §2, sequences §4–6, deployment §8). Use the existing class colors: green for new, grey for existing, blue for external.
3. Get user sign-off before implementing, then follow A or B.

The known enhancement directions and their constraints are in [references/enhancements.md](references/enhancements.md).

## Review checklist (use for every rpc-mcp change)

- [ ] No rpc-go package is imported from `mcp/`, and the root `go.mod` has no MCP SDK dependency (D2, D3).
- [ ] Every tool input that reaches rpc argv is validated (enum or allow-list). No secret or URL comes from tool input (D6).
- [ ] Destructive tools have `DestructiveHint`, a `confirm` gate, are hidden by `--read-only`, and their description warns about self-termination.
- [ ] Read-only tools have `ReadOnlyHint` and `IdempotentHint`.
- [ ] Output is rpc's JSON object; nothing is printed to rpc-mcp's stdout in stdio mode (logs go to stderr).
- [ ] Errors come back as tool errors with hints, and the timeout fits the command.
- [ ] New rpc commands follow D4 and CLAUDE.md (AMTBaseCmd flow, typed errors, mocks regenerated, `--json`).
- [ ] Tests: `fakeRPC` for rpc-mcp, gomock for rpc commands. No test starts the real rpc or touches hardware.
- [ ] README (capabilities, inputs, config, troubleshooting) and ARCHITECTURE.md (tables, diagrams, decisions) are updated.

## Verify

```sh
# rpc-mcp module
cd mcp && go test ./... && go vet ./... && go build -o rpc-mcp .
# rpc-go root (independent of mcp/)
go build ./... && go test ./internal/commands/ ./internal/cli/
# stdio smoke test: initialize, tools/list, call a read-only tool
npx @modelcontextprotocol/inspector ./mcp/rpc-mcp --rpc-path ./rpc
```

On real hardware, run elevated on an activated device with `AMT_PASSWORD` set. Leave destructive actions until last.

## Known pitfalls

- **CRLF checkout on Windows:** `gofumpt -l` lists every file. Check formatting on LF-normalized content (`tr -d '\r' < f.go > /tmp/x.go && gofumpt -extra -l /tmp/x.go`).
- **Local golangci-lint may be older than Go 1.27** and refuses to load the config. Use the Dockerized lint command from CLAUDE.md.
- **Pre-existing failing tests** (the activate post-sync tests and the amtinfo sync 404 POST-fallback tests) fail on an unmodified tree. Confirm with `git stash -u` before blaming your change.
- **rpc exits with 10** when Kong wraps a typed error from `AfterApply`. Read the `Error <N>:` prefix of the logged message instead.
- **DMTF vs AMT power names differ** (8 is "OffSoft" in DMTF but a hard off on AMT). Use the `power` package constants and expose action names.
- **rpc reads `config.yaml` from its working directory**, so a stray file there changes flag defaults.
- **`make mcp` needs `.PHONY: mcp`**, because a directory with the same name exists.
- **Power actions on the local host end the agent session.** Test them last and never in automated runs.
