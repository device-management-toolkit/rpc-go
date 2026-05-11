# GitHub Copilot Instructions

See **[../CLAUDE.md](../CLAUDE.md)** — the canonical guide for AI coding assistants in this repository. The content is tool-neutral and applies to GitHub Copilot Chat / Copilot Workspace just as it does to any other agent. Edit `CLAUDE.md`; this file is a pointer.

**Branch scope:** this guide describes the v3 (`main`) architecture. The `2.x.x` maintenance branch has a different layout (flat `internal/flags/`, `cleanenv`, no `commands/`/`orchestrator/` packages) and will get its own `CLAUDE.md` — do not port v3 patterns there.

Key non-negotiables (full detail in `CLAUDE.md`):

- **CLI is Kong-based.** Subcommands are struct fields with `cmd:""`; hierarchies form by struct embedding. Shared flag groups (`Globals`, `commands.ServerAuthFlags`, `commands.AMTBaseCmd`) are embedded structs. **When editing CLI shape, check the upstream docs at <https://github.com/alecthomas/kong>** — many web examples are stale.
- **Embed `AMTBaseCmd` on every command that touches AMT; embed `ConfigureBaseCmd` on every `configure` subcommand.** WSMAN client setup is lazy via `EnsureRuntime` / `EnsureAMTPassword` / `EnsureWSMAN`. Don't try to build a WSMAN client outside that flow — you'll race the lifecycle and break mocks.
- **Never hand-author WSMAN XML.** All WSMAN goes through `github.com/device-management-toolkit/go-wsman-messages/v2` via the `internal/interfaces/WSMANer` seam. Missing messages are fixed upstream in `go-wsman-messages`, not crafted here.
- **The orchestrator re-invokes `rpc` as a subprocess per step** (`internal/orchestrator/`). Match exit codes (`ExecError.ExitCode` → `utils.CustomError.Code`), not output substrings. Verbose Digest logs make substring matching unreliable.
- **Four activation modes** (`runRemoteActivation`, `runHttpProfileFullflow`, `runLocalProfileFullflow`, `runLocalActivation`) live behind one `activate` verb. `Validate()` in `internal/commands/activate/activate.go` is the gatekeeper — add cross-flag invariants there before adding behaviour to a `run*` method.
- **Legacy ws/wss RPS path (`internal/rps/`) must not regress.** Many v2 integrators depend on it. Add new behaviour to the HTTP-profile path instead.
- **Two distinct cert-skip flags.** `--skip-cert-check` → remote RPS/Console HTTPS/WSS. `--skip-amt-cert-check` → AMT/LMS local TLS. Keep them straight.
- **HECI/MEI requires root/Administrator.** Commands that tolerate missing privileges set `SkipWSMANSetup = true`; others fail with `utils.IncorrectPermissions` and `cli.Execute` offers to self-elevate on interactive TTYs.
- **Cross-platform:** rpc-go ships on Linux + Windows. OS-specific behaviour goes behind build tags (`pkg/heci/heci_linux.go` vs `pkg/heci/heci_windows.go`, `pkg/utils/elevate*.go`, `pkg/windows/`), not at runtime. On Windows shells chain commands with `;`, not `&&`.
- **Module path is `github.com/device-management-toolkit/rpc-go/v2`** — the `/v2` is historical and is kept across the v3 release. Don't try to "fix" it.
- **Small, focused PRs.** No scope creep. Stack prerequisite refactors as `refactor:` / `test:` / `build:` ahead of the `feat:` that triggers a release.
- **Conventional Commits enforced** by commitlint + semantic-release. On `main` (beta channel): `feat:` → minor prerelease, `fix:`/`perf:`/`chore:` → patch, `BREAKING CHANGE:` → major. `scope-enum` is enforced by `.github/commitlint.config.cjs` — see `CONTRIBUTING.MD` for the valid list.
- **Before declaring done:** `go test ./...`, `gofumpt -l -w -extra ./` (no diff), `go vet ./...`, and `docker run --rm -v .:/app -w /app golangci/golangci-lint:latest golangci-lint run -v --fix` (use `-v ${pwd}:/app` on Windows PowerShell — no remaining diagnostics) all green. Run `make mock` if you touched a mocked interface and commit the result; run `make fuzz-regression` if you touched `internal/cli/` parsing.
