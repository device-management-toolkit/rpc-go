# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Canonical guide for AI coding assistants working on the `main` (v3.x) branch of rpc-go. The content is tool-neutral and applies to any agent (Claude Code, Codex, Cursor, Aider, Continue, Gemini CLI, GitHub Copilot, etc.). Edit this file; pointer files (`AGENTS.md`, `.github/copilot-instructions.md`) should reference it.

## Branch scope

**This file is the v3 (`main`) guide. It is not accurate for the `2.x.x` maintenance branch.**

- **`main` — v3.0.0 beta (this file).** Refactored around Kong CLI, a `commands/` package hierarchy, the **`orchestrator/` subprocess driver**, and the new RESTful profile-export activation flow. Publishes to the `beta` channel.
- **`2.x.x` — v2.x maintenance.** Different architecture: flat `internal/flags/` parser, `cleanenv` for config, no `commands/`/`orchestrator/` packages, legacy ws/wss-only remote activation. That branch will get its own `CLAUDE.md`; do not port v3 guidance there and do not port v2 patterns here.

When in doubt about which branch you're on: `go.mod` declares module `github.com/device-management-toolkit/rpc-go/v2` on both (the major in the module path is historical and will not be bumped for v3). The discriminators are package layout (`internal/commands/`, `internal/orchestrator/`, `internal/cli/cli.go` with Kong) and `v3.0-changes.md` at the repo root.

## Overview

Remote Provisioning Client (RPC) is a single-binary tool — and optional C-shared library — that activates, configures, deactivates, and reports on Intel® AMT devices. It runs **on the managed device itself**, talking to AMT firmware locally through the HECI/MEI driver (admin/root required), and optionally to a remote server (RPS or Console) for orchestration or profile delivery. Same binary, three deployment shapes:

- **Local CLI:** `rpc <command>` on the target device. Default invocation with no command runs `amtinfo`.
- **Subprocess orchestrator:** the same binary re-invokes itself (`rpc activate --acm …`, `rpc configure cira …`, …) to execute a multi-step profile end-to-end. See [Profile orchestration](#profile-orchestration-the-subprocess-model).
- **C-shared library:** `cmd/rpc/lib.go` exports `rpcExec` and `rpcCheckAccess` for embedding in C/C++/.NET/etc. consumers (`go build -buildmode=c-shared`).

**v3 is a breaking release.** Three things changed at the surface (full detail in `v3.0-changes.md`):

1. Flags require explicit `--long` / `-short` syntax; bare `-long` no longer works.
2. `config` now means **application configuration** (the YAML that mirrors CLI flags, default `config.yaml`). The old `configv2` flag is gone.
3. The old "configuration profile" concept is now called a **profile** and is passed as `--profile <file-or-name>`. The flag does double duty: a path/extension-bearing string is a local profile file; a bare name is a legacy RPS profile name (requires `--url wss://…`).

Activation has three distinct code paths and the flag combinations choose between them — keep them straight when editing `internal/commands/activate/`:

| Mode | Trigger | Code path | What rpc-go does |
|---|---|---|---|
| **Legacy remote (RPS)** | `--url wss://…` + `--profile <name>` | `internal/rps/` | Opens WebSocket to RPS; RPS sends WSMAN messages, rpc-go relays them to AMT. rpc-go is a dumb pipe. |
| **HTTP profile fullflow** | `--url https://…/api/v1/admin/profiles/export/<name>` | `internal/profile/fetcher.go` + `internal/orchestrator/` | rpc-go authenticates, fetches the encrypted profile, decrypts, registers the device with Console, then orchestrates the steps itself by re-invoking `rpc <subcmd>`. |
| **Local profile file** | `--profile path/to/profile.yaml` (with `--key` if encrypted) | `internal/profile/local.go` + `internal/orchestrator/` | Same orchestrator as HTTP fullflow, but the profile is loaded from disk. |
| **Local direct** | `--local --ccm` / `--local --acm` (no profile) | `internal/commands/activate/local.go` | Direct single-step activation using flags. No orchestrator. |

The HTTP-fullflow path is the v3 headline feature — orchestration moves from RPS to rpc-go, dramatically cutting time-to-activation. Until that DX is polished, the legacy ws/wss flow is still supported and **must not regress**.

## Commands

**Go 1.25+ required** (per `go.mod`). **Module path is `github.com/device-management-toolkit/rpc-go/v2`** — the `/v2` is historical (kept across the v3 release) and **all intra-repo imports use that prefix**. Don't try to "fix" it.

HECI/MEI access requires **administrator / root**. Local AMT commands (`amtinfo` excepted in degraded mode) fail with `IncorrectPermissions` when not elevated; on interactive terminals the CLI offers to self-elevate.

### Running

```sh
# bash/zsh
go run ./cmd/rpc/main.go <command> [flags]

# PowerShell — note: chain with ';' not '&&'
go run .\cmd\rpc\main.go <command> [flags]
```

A bare invocation defaults to `amtinfo` (`internal/cli/cli.go:Execute` injects the command when none is present), so `rpc` and `rpc amtinfo` behave the same. Help still works (`rpc --help`, `rpc configure --help`, etc.) because `--help`/`-h` short-circuits the default-command injection.

The `.vscode/launch.json` ships configurations for the common scenarios (activate via wss, activate local with config.yaml, amtinfo, deactivate, …). All use `"asRoot": true` and `"buildFlags": ["-race"]` — prefer those over hand-built `go run` lines when iterating on local AMT flows; you need elevation either way.

### Building

```sh
# Executable
go build -o rpc      ./cmd/rpc/main.go          # Linux/macOS
go build -o rpc.exe  ./cmd/rpc/main.go          # Windows

# C-shared library (requires CGO + a working gcc/MSVC toolchain)
CGO_ENABLED=1 go build -buildmode=c-shared -o librpc.so  ./cmd/rpc   # Linux
go build -buildmode=c-shared -o rpc.dll ./cmd/rpc                    # Windows
```

`build.sh <version>` is the release-time wrapper used by semantic-release; it cross-compiles the matrix the `.releaserc.json` ships as GitHub release assets (`rpc_linux_x64.tar.gz`, `rpc_linux_x86.tar.gz`, `rpc_windows_x64.exe`, `rpc_windows_x86.exe`, `rpc_so_x64.tar.gz`). Local dev doesn't need it.

### Testing

```sh
go test ./...                                                   # whole suite
go test ./internal/commands/activate                            # one package
go test -run '^TestActivate_Local$' ./internal/commands/activate # one test
go test ./... -coverprofile=coverage.out -covermode=atomic      # with coverage (matches CI)
go tool cover -func=coverage.out                                # coverage report
```

CI runs `go test ./... -coverprofile=coverage.out -covermode=atomic`; `-race` is **not** enabled at the repo level today (unlike sibling repos) — feel free to add it locally when chasing data-race symptoms but don't add it as a CI default in passing.

Tests rely on:

- `go.uber.org/mock` (`gomock`) for interface mocks. Regenerate with `make mock` after editing `internal/interfaces/wsman.go` or `pkg/amt/commands.go`.
- `github.com/stretchr/testify/require` + `assert` for assertions.

### Fuzz tests

Fuzz targets live in `internal/cli/cli_fuzz_test.go` (currently the deactivate command parsing surface — the historically panic-prone area). Standard helpers:

```sh
make fuzz-short           # 30s per target — the PR-time smoke
make fuzz                 # 5m per target  — local thorough run
make fuzz-regression      # corpus replay only, no new inputs (1x execution)
go test -fuzz=^FuzzDeactivate$ -fuzztime=1m ./internal/cli  # ad-hoc one target
```

Seed corpora live under `internal/cli/testdata/fuzz/` and are committed. Crashes discovered in CI (`.github/workflows/fuzz.yml`) are uploaded as artifacts; **commit reproducers back into the corpus** when fixing.

### Mocks

```sh
make mock
```

The `make mock` target encodes the canonical `mockgen -source <interface> -destination …` invocations:

- `internal/interfaces/wsman.go` → `internal/mocks/wsman_mock.go`
- `internal/amt/commands.go` → `internal/mocks/amt_mock.go` (note: the legacy `internal/amt/` path comes from v2 layout and is still referenced by the Makefile — confirm before editing)

Commit the regenerated mocks in the same PR as the interface change. Stale mocks are a top cause of "passes locally, fails CI."

### Linting and formatting

CI rejects unformatted or unlinted code. The pre-push triplet:

```sh
gofumpt -l -w -extra ./                              # format (one-time install: go install mvdan.cc/gofumpt@latest)
go vet ./...                                         # vet

# Dockerized golangci-lint — same .golangci.yml CI uses
# bash/zsh:
docker run --rm -v .:/app -w /app golangci/golangci-lint:latest golangci-lint run -v --fix
# PowerShell:
docker run --rm -v ${pwd}:/app -w /app golangci/golangci-lint:latest golangci-lint run -v --fix
```

What CI actually does: `gofmt -s -l . | wc -l` must be zero, then `reviewdog/action-golangci-lint` runs against `./.golangci.yml`. `gofumpt -extra` is a strict superset of `gofmt -s`, so anything passing it also passes CI's formatter; linter binary versions aren't pinned identically, so occasional skew on bleeding-edge linters is possible.

`.golangci.yml` is strict:

- **Style:** `gofumpt` (extra rules), `gci` for import ordering, `wsl_v5` for whitespace/separator rules (`allow-first-in-block: true`, `branch-max-lines: 2`).
- **Bugs:** `staticcheck`, `errcheck` (`check-type-assertions: true`), `errorlint` (`%w` required on wraps), `bodyclose`, `noctx`, `nakedret`, `ineffassign`, `predeclared`, `durationcheck`, `makezero`.
- **Complexity:** `cyclop` 15, `funlen` 100 lines / 45 statements, `gocognit` 16, `nestif` 5.
- **Quality:** `goconst` (min-len 2, min-occurrences 3), `mnd`, `misspell` (US locale), `unconvert`, `unparam`, `nlreturn`, `dogsled`, `nolintlint` (require explanation + specific).
- **Exclusions:** `err113`, `funlen`, `nestif`, `goconst` are relaxed in `*_test.go`; `paralleltest` and `godot` relaxed in `integration-test/`.
- `gosec` excludes G115 (integer overflow) — already too noisy on our integer math.

`mnd` (magic-number detector) is on for arguments/case/condition/operation/return — extract constants when you find yourself fighting it. Don't `//nolint` without a `// because: <reason>` per `nolintlint`.

## Architecture

rpc-go is intentionally small and procedural. The layout is:

```
cmd/rpc/                       // entry points
  ├─ main.go                   // executable: calls cli.Execute(os.Args)
  └─ lib.go                    // C-shared library: rpcExec / rpcCheckAccess via cgo

internal/cli/cli.go            // Kong parser construction + Execute / ExecuteWithAMT.
                               //   Wires kong-yaml config file, BindToProvider for amt.Interface DI,
                               //   default-to-amtinfo, self-elevation on IncorrectPermissions.

internal/commands/             // every CLI verb lives here
  ├─ base.go                   // AMTBaseCmd  — the lifecycle base (see "Command lifecycle" below)
  ├─ auth.go                   // ServerAuthFlags — embedded into commands that talk to RPS/Console
  ├─ shared.go                 // commands.Context — DI struct passed to every Run()
  ├─ amtinfo.go / version.go / deactivate.go        // simple verbs
  ├─ activate/                 // activate <flags>  — mode-detected (local / wss / https-profile / file)
  │    ├─ activate.go          //   top-level Validate/Run that dispatches
  │    ├─ local.go             //   local single-step activation
  │    └─ remote.go            //   legacy ws/wss path that delegates into internal/rps
  ├─ configure/                // configure <sub> [...] — each tunable is its own subcommand
  │    ├─ configure.go         //   ConfigureCmd composition + ConfigureBaseCmd (EnsureRuntime)
  │    └─ mebx.go / amtpassword.go / amtfeatures.go / enableamt.go / disableamt.go /
  │       cira.go / syncclock.go / wifisync.go / wireless.go / wired.go / tls.go /
  │       proxy.go / synchostname.go
  └─ diagnostics/              // diagnostics (alias: diag)

internal/orchestrator/         // profile driver — re-invokes the rpc binary per step
  ├─ orchestrator.go           //   ProfileOrchestrator.ExecuteProfile()
  └─ executor.go               //   CLIExecutor (exec.Command-based) + ExecError + DirectExecutor (tests)

internal/profile/              // profile loading: local YAML, encrypted local, HTTP(S) fetch + auth
internal/rps/                  // legacy WebSocket client to RPS (the ws/wss activation path)
internal/lm/                   // Local Management Service / Engine connection helpers
internal/local/amt/            // adapter that builds a go-wsman-messages WSMAN client over LMS
internal/certs/                // TLS configs, embedded trusted store, Enterprise Assistant helper
internal/device/               // Console REST client (AddDevice / UpdateDevice / ClearMPSPassword)
internal/interfaces/           // WSMANer + other interfaces — the seam that gets mocked
internal/mocks/                // generated — do not hand-edit

pkg/                           // public surface (importable by external consumers, e.g. the lib build)
  ├─ amt/                      // amt.Interface — high-level HECI-backed AMT command wrapper
  ├─ heci/                     // HECI/MEI driver bindings (Windows + Linux)
  ├─ pthi/                     // Platform Trust Host Interface protocol
  ├─ utils/                    // exit codes (utils.CustomError), prompts, elevation, paths, constants
  ├─ smb/                      // SMB helper for fetching profiles from share paths
  ├─ network/                  // DHCP/IP helpers
  ├─ upid/                     // UPID handling
  ├─ hotham/                   // Hotham (in-band AMT discovery / activation helper)
  ├─ version/                  // build-injected version + git hash
  └─ windows/                  // win32 syscalls (elevation, console)
```

The composition root is `internal/cli/cli.go:Execute`. It constructs the Kong parser, binds the `amt.Interface` provider, parses, builds a `commands.Context`, and calls `kctx.Run(appCtx)` to dispatch into the selected command's `Run(ctx)` method.

### Kong CLI hierarchy (READ THIS BEFORE EDITING COMMANDS)

We use **`github.com/alecthomas/kong`** for parsing. Kong's tag-driven model is non-obvious in places and the wider internet has plenty of stale examples — **when in doubt, check the upstream docs and source at <https://github.com/alecthomas/kong>** (`kong.Context`, `kong.Visit`, `BindToProvider`, `Configuration`, `AfterApply`). What this repo does specifically:

- **Top-level CLI is a struct.** `internal/cli/cli.go:CLI` embeds `Globals` (shared flags) and `commands.ServerAuthFlags` (shared auth flags), then declares one field per top-level command with a `cmd:""` tag:

  ```go
  type CLI struct {
      Globals
      commands.ServerAuthFlags

      AmtInfo     commands.AmtInfoCmd        `cmd:"" name:"amtinfo" help:"…"`
      Activate    activate.ActivateCmd       `cmd:"activate" help:"…"`
      Configure   configure.ConfigureCmd     `cmd:"configure" help:"…"`
      Deactivate  commands.DeactivateCmd     `cmd:"deactivate" help:"…"`
      Version     commands.VersionCmd        `cmd:"version" help:"…"`
      Diagnostics diagnostics.DiagnosticsCmd `cmd:"diagnostics" aliases:"diag" help:"…"`
  }
  ```

- **Subcommands nest by embedding command structs as fields with `cmd:""`.** E.g. `ConfigureCmd` declares `MEBx MEBxCmd \`cmd:"" name:"mebx" aliases:"setmebx"\``, `TLS TLSCmd \`cmd:"" aliases:"tls,configuretls"\``, etc. The Kong tree mirrors the struct tree. To add a new `configure` verb, add a field with `cmd:""` to `configure.ConfigureCmd` and implement `Validate()`/`Run(ctx *commands.Context) error` on the struct. Don't manually register anywhere — Kong walks the tree.
- **Shared flag groups are embedded structs.** `Globals`, `commands.ServerAuthFlags`, and `commands.AMTBaseCmd` are all embedded. Flag tags (`help:"…"`, `name:"…"`, `short:"…"`, `env:"…"`, `default:"…"`, `enum:"…"`) live on the fields. Fields tagged `kong:"-"` are skipped by the parser (we use this on `WSMan`, `ControlMode`, etc. inside `AMTBaseCmd` — those are runtime-only state).
- **Validation hook:** any command that implements `Validate() error` is called by Kong after flag binding. Use it for cross-flag invariants (e.g. `activate` checks `--url` scheme + mode flag combinations).
- **Lifecycle hook:** any command that implements `AfterApply(deps…) error` is called by Kong after `Validate`. Kong injects dependencies from `BindToProvider`. `AMTBaseCmd.AfterApply(amtCommand amt.Interface)` is the canonical example — see below. Make `AfterApply` **idempotent** (we track this via `afterApplied bool`); Kong can call it more than once across the tree.
- **Dependency injection:** in `cli.go` we do `kong.BindToProvider(func() amt.Interface { return amtCommand })`. Anywhere downstream that takes `amt.Interface` as a parameter (`AfterApply`, `Run`) gets the bound value. To add a new injected dependency, add a `BindToProvider` line and accept the type as a parameter; don't reach into globals.
- **YAML defaults:** `kong.Configuration(kongyaml.Loader, "config.yaml")` makes every flag's default-resolvable from `config.yaml` keys with the same name as the flag (`name:` tag wins over field name). CLI args and env vars override YAML. The YAML loader is best-effort — a missing file is fine, a malformed file is fatal.
- **Aliases** go on the field tag (`aliases:"syncclock,synctime"`). Use them liberally on `configure` subcommands; we have many users on legacy command names from v2.
- **Help:** `kong.UsageOnError()` makes parse errors print usage. `cli.go:PrintHelp` re-parses with `--help` appended to render contextual help for partial command trees.
- **Never infer the actual flag name from the `name:"..."` struct tag alone.** Kong's tag handling is subtle: when a field also carries `kong:"required"` (or other `kong:"..."` directives), Kong derives the flag name from the kebab-cased Go field name rather than the bare `name:` tag. Concrete example in this repo — `configure.CIRACmd.MPSAddress` is declared `\`help:"MPS Address" env:"MPS_ADDRESS" name:"mpsaddress" kong:"required"\`` but Kong exposes it as **`--mps-address`**, not `--mpsaddress`. The neighbouring `MPSPassword` field (no `kong:"required"`) does respect its `name:"mpspassword"` tag and shows up as `--mpspassword`. **The only authoritative source for a Kong flag name is `go run ./cmd/rpc/main.go <command> --help`** — verify there before raising any "the struct tag says X but the orchestrator passes Y" finding. The orchestrator's `--mps-address` / `--mps-cert` invocations are correct.

For anything more exotic — custom mappers, alternate config loaders, hidden flags, `BeforeReset`, `Resolver`s — go read [`github.com/alecthomas/kong`](https://github.com/alecthomas/kong). The README has the authoritative tag table; `kong/`* source files have the runtime semantics that the README glosses over.

### Command lifecycle (`AMTBaseCmd`)

Almost every command that touches AMT embeds `commands.AMTBaseCmd`. Its `AfterApply(amtCommand amt.Interface) error` runs **once** per invocation and:

1. Aborts early with `utils.IncorrectPermissions` when not elevated (the outer `cli.Execute` then offers to self-elevate on interactive TTYs). Commands that tolerate missing privileges set `SkipWSMANSetup = true` and get a degraded path (this is how `amtinfo` works without root).
2. Calls `amtCommand.GetControlMode()` with retries (4 attempts, 4s backoff) so transient HECI busyness doesn't fail the whole command.
3. Reads `GetChangeEnabled()` to detect TLS-enforced local ports (`LocalTLSEnforced`); this changes how WSMAN clients are dialed downstream.
4. Closes the MEI handle (`defer amtCommand.Close()`) — **holding it in the parent process blocks orchestrator subprocesses on Windows**, see comment in `orchestrator.go`.

`AMTBaseCmd` does **not** set up the WSMAN client during `AfterApply` (we don't have the password yet). Instead each command's `Run` calls `EnsureAMTPassword(ctx, cmd)` (which prompts if needed, with confirm-on-typo when control mode 0) and then `EnsureWSMAN(ctx)` to lazily build the WSMAN client. `ConfigureBaseCmd.EnsureRuntime` is the standard helper that runs both. **Call it at the top of every new `configure` subcommand `Run`** — don't try to set up WSMAN earlier.

Commands that conditionally need a password override `RequiresAMTPassword() bool` (e.g. `ActivateCmd` returns `false` when `--stopConfig` is set; `amtinfo` returns `false` unless `--userCert` is asked for).

### Profile orchestration (the subprocess model)

When activation is driven by a profile (HTTP fullflow or local file), `internal/orchestrator/orchestrator.go:ProfileOrchestrator.ExecuteProfile` runs the steps **by re-invoking the same `rpc` binary as a subprocess for each step** (`internal/orchestrator/executor.go:CLIExecutor`). The argv looks like `rpc --password <new> configure cira --mps-address … --mps-cert …`.

This is unusual and intentional:

- **Each step is isolated.** A WSMAN session leak, an AMT firmware quirk, or a HECI lock won't bleed into the next step.
- **Failures are typed by exit code.** `ExecError.ExitCode` matches `utils.CustomError.Code` — the orchestrator gates retries on the code (e.g. `AMTAuthenticationFailed` triggers the password-rotation fallback in `executeWithPasswordFallback`). **Never substring-match subprocess output** — verbose Digest logs make that unreliable.
- **Password rotation is interleaved.** Mid-orchestration, if a step authenticates and fails with `AMTAuthenticationFailed`, the orchestrator prompts (up to 3 attempts) for the current AMT password, calls `rpc configure amtpassword --password <old> --newamtpassword <new>`, and retries the original step.
- **Step order is fixed** (`ExecuteProfile` sequence): activation → MEBx → AMT features → wired → WiFi enable → wireless profiles (with `--purge` first) → TLS → CIRA → HTTP proxy. CIRA failures wrap `ErrCIRAConfiguration` so callers can clear the MPS password from Console on failure.

When adding a new orchestrated step:

1. Implement the underlying `configure <name>` subcommand the normal way (struct in `internal/commands/configure/`, validate, run, tests).
2. Add an `executeXxx()` method on `ProfileOrchestrator` that calls `po.baseArgs()` then appends `"configure", "<name>", "--flag", value, …` and finishes with `po.executeWithPasswordFallback(args)`.
3. Splice it into `ExecuteProfile()` in the correct position relative to AMT firmware dependencies.
4. Test it with `DirectExecutor` (the test-only `CommandExecutor` that swallows args) — never shell out in unit tests.

`baseArgs()` is the canonical argv prefix and already includes `--skip-amt-cert-check` and `--password` and propagates verbose. Use it.

### Legacy RPS path (`internal/rps`)

The ws/wss path (`activate --url wss://… --profile <name>`, `deactivate --url …`, maintenance commands) opens a WebSocket to RPS and lets RPS decide what to do. rpc-go's role is to relay WSMAN messages between RPS and AMT and respond to specific protocol prompts. **This path must keep working** — many existing v2 integrators depend on it. Behaviour changes here need explicit approval; prefer adding new behaviour to the HTTP-profile path instead.

### HECI / LMS / WSMAN layering

```
your command
  └─ AMTBaseCmd lifecycle
       ├─ amt.Interface (pkg/amt)             // pkg/heci + pkg/pthi over MEI/HECI ioctls
       │   └─ GetControlMode, GetUUID, GetVersion, Close, …
       └─ EnsureWSMAN → localamt.NewGoWSMANMessages(LMSAddress)
            └─ go-wsman-messages WSMAN client targeting LMS on :16992/:16993
                 └─ internal/lm/ Local Management Service connection
                      └─ AMT firmware
```

Two distinct cert-check flags govern TLS verification on each side and they are not interchangeable:

- `--skip-cert-check` / `SkipCertCheck` — applies to **remote** RPS/Console HTTPS/WSS connections.
- `--skip-amt-cert-check` / `SkipAMTCertCheck` — applies to the **AMT/LMS** TLS connection over local ports.

When wiring something new through Kong, keep them straight; conflating them lets remote certs slip past verification.

### C-shared library (`cmd/rpc/lib.go`)

The library exports `rpcExec(Input, **Output, **ErrOutput) int` and `rpcCheckAccess() int`. Input is a CSV-quoted argv string; the C library hijacks stdout/stderr, runs `cli.ExecuteWithAMT(args, amtCommand)`, restores the streams, and returns the exit code (`utils.CustomError.Code`). Two consequences:

- **Don't write directly to `os.Stdout` from command code** if you want the lib build to capture it — go through the existing logger or output helpers.
- **Keep `cli.Execute` and `cli.ExecuteWithAMT` parallel.** `Execute` is the executable entry point and wires self-elevation; `ExecuteWithAMT` is the lib entry point and skips elevation (the host process is responsible). New top-level behaviour added to `Execute` must be reflected (or explicitly *not* reflected, deliberately) in `ExecuteWithAMT`.

## Implementation guidelines (non-negotiable)

- **Never hand-author WSMAN XML.** All WSMAN goes through `github.com/device-management-toolkit/go-wsman-messages/v2`. Use the existing `internal/interfaces/WSMANer` seam and `internal/local/amt` adapter. If a needed message isn't in `go-wsman-messages`, **fix it upstream** rather than crafting raw XML here — `go-wsman-messages` is a sibling repo in the device-management-toolkit org and accepts contributions.
- **Embed `AMTBaseCmd` on every command that touches AMT; embed `ConfigureBaseCmd` on every `configure` subcommand.** Don't try to set up the WSMAN client outside the documented `EnsureRuntime` / `EnsureAMTPassword` / `EnsureWSMAN` flow — you'll race with the lifecycle and break the test mocks.
- **Don't substring-match subprocess output in the orchestrator.** Use `ExecError.ExitCode` (it matches `utils.CustomError.Code`). Add a new `utils.CustomError` if you need a new signal.
- **Keep the two activation paths cleanly separated.** `internal/rps/` is the legacy ws/wss path and must keep working. The HTTP-fullflow path lives in `internal/profile/`, `internal/orchestrator/`, and `internal/commands/activate/activate.go:runHttpProfileFullflow`. Don't fork them with shared mutable state; if you need shared helpers put them in `internal/device/` or `internal/profile/`.
- **CLI tags and YAML keys must match.** `kong-yaml` looks up config keys by the flag's `name:` tag (or kebab-cased field name when `name:` is absent). When you rename a flag, audit `config.yaml`/`config.sample.yaml` and any `env:` tags in the same change — environment variables override YAML and CLI overrides both.
- **Magic numbers and strings are linter-enforced.** `mnd` and `goconst` (≥3 occurrences, ≥2 chars) will catch the obvious cases. Constants live next to the consumer (e.g. `configure.RemoteTLSInstanceId`) or in `pkg/utils` when truly shared.
- **`%w` on every error wrap.** `errorlint` is on. New sentinel errors are package-scope `var ErrFoo = errors.New("…")` and get matched with `errors.Is`/`errors.As`.
- **Mind `wsl_v5`.** Blank lines around blocks, `if/return` clustering, branch-max-lines 2 — let `gofumpt -extra` + `golangci-lint --fix` do the mechanical pass.
- **Tests do not run in parallel today** (no `paralleltest` linter, no `-race` in CI). When writing fresh tests, default to subtests + `tt := tt` capture so we can flip those on later without churn.
- **Cross-platform constraints are real.** rpc-go ships on Linux and Windows. HECI/MEI implementations diverge per OS (`pkg/heci/heci_linux.go` vs `pkg/heci/heci_windows.go`); elevation, console handling, and path conventions diverge too (`pkg/utils/elevate*.go`, `pkg/windows/`). New OS-specific behaviour goes behind build tags, not at runtime.
- **Admin-only is the default.** HECI requires root/Administrator; commands that don't need HECI (`version`) skip `AMTBaseCmd`; commands that *prefer* HECI but can degrade (`amtinfo` without `--userCert`) set `SkipWSMANSetup = true` and check `HECIAvailable`. Don't paper over missing privileges with silent fallbacks — fail with `utils.IncorrectPermissions` and let `cli.Execute` handle elevation.
- **Keep PRs small and scoped to one concern.** A focused 50–150-line diff gets reviewed and merged; a 500-line "while I was in there" diff stalls and risks regressions in unrelated activation paths. Unrelated bug / dead-code / lint-nit / formatting drift you notice while working belongs in a **separate** PR. **Do not scope-creep.**
- **Work in incremental phases — this is an agile team.** Plan features as a sequence of small, independently-reviewable PRs rather than one big bang. If a PR grows past the point where a reviewer can hold it in their head (rough rule of thumb: a few hundred meaningful lines, or more than one logical concern), stop and break it into smaller PRs that stack. Each PR should leave `main` in a working state.
- **Order PRs around the semver release impact.** Releases are automated by semantic-release (`.releaserc.json`) from conventional commits. On `main` (the v3 prerelease channel): `feat:` cuts a **minor** prerelease, `fix:`/`perf:` cuts a **patch**, `chore:` is configured to cut a **patch**, `BREAKING CHANGE:` cuts a **major**, and `refactor:`/`docs:`/`test:`/`style:`/`build:`/`ci:` cut **no release**. When a feature needs prerequisite plumbing (extracted helpers, internal API reshaping, test scaffolding), land those prerequisites first as `refactor:` / `test:` / `build:` so they ship invisibly; the final user-visible PR is the `feat:` that flips the switch and triggers the release. Don't bundle prerequisites into a `feat:` commit just to save PRs.
- **Touching `activate`? Trace all four modes.** `runRemoteActivation` (wss), `runHttpProfileFullflow` (https), `runLocalProfileFullflow` (file), `runLocalActivation` (--ccm/--acm). The `Validate()` method in `activate.go` is the gatekeeper — it disallows mode-flag combinations that would silently take the wrong path. Add invariants there before you add behaviour to a `run*` method.
- **Before declaring work done, all of these must be green:** `go test ./...`, `gofumpt -l -w -extra ./` (no diff), `go vet ./...`, and the Dockerized `golangci-lint run` (no remaining diagnostics). Run `make mock` if you touched a mocked interface and commit the result. Run `make fuzz-regression` if you touched `internal/cli/` parsing.

## Commit conventions (see CONTRIBUTING.MD)

Conventional Commits, semantic-release-driven. Format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Each line ≤72 characters; commitlint enforces `body-max-line-length: 200`. The header is mandatory; scope is optional but reviewers usually expect one.

**Types** (with release impact on `main`'s `beta` channel):

| Type | Release |
|---|---|
| `feat` | minor (prerelease) |
| `fix` | patch |
| `perf` | patch |
| `chore` | patch (`.releaserc.json` rule) |
| `revert` | reverts a prior commit |
| `docs` / `style` / `refactor` / `test` / `build` / `ci` | no release |
| any body containing `BREAKING CHANGE:` | major |

**Scopes** are enforced by `.github/commitlint.config.cjs:scope-enum`. The valid list is:

`lme`, `lms`, `lmx`, `utils`, `cli`, `rps`, `heci`, `pthi`, `sample`, `docker`, `deps`, `deps-dev`, `gh-actions`, `config`, `internal`, `local`

Pick the most specific match. Use `internal` for commands/orchestrator/profile changes that don't fit a more specific scope. Use `cli` for Kong-level changes in `internal/cli/`. Multi-area changes are usually a sign the PR should be split (see [small PRs](#implementation-guidelines-non-negotiable)).

**Footer** references the GitHub issue this commit closes, using a [closing-keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue) — `Closes: #1234`, `Fixes: #1234`, or `Resolves: #1234` — so the issue auto-closes on merge. Breaking changes start with `BREAKING CHANGE:` in the footer.

**PR practices:**

- **PR title follows the same header rules.** A `semantic.yml` check enforces this.
- **PR author merges.** Choose `Rebase and merge` or `Squash and merge` to preserve linear history.
- **Update `config.sample.yaml` / `config.yaml` when adding flags.** They are the canonical user-facing reference for the YAML surface.
- **Update `v3.0-changes.md`** if you introduce a v3 breaking change relative to v2 that users will hit on upgrade.
