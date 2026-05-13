# Contributing to rpc-go

Thanks for helping out! This guide covers the conventions our automated tooling and reviewers expect. For deeper architectural and implementation guidance, see [CLAUDE.md](./CLAUDE.md) — it's the canonical reference for both humans and AI coding assistants.

**Branch scope:** this guide and `CLAUDE.md` describe the v3 (`main`) line. The `2.x.x` maintenance branch has a different architecture and will get its own docs — don't port v3 patterns there.

## <a name="commit"></a> Commit Message Guidelines

We have precise rules over how our git commit messages should be formatted. This keeps the history readable and drives our **semantic-release** automation (`.releaserc.json`) — your commit type determines whether a release is cut and at what level.

### Commit Message Format

Each commit message consists of a **header**, a **body** and a **footer**. The header has a special format that includes a **type**, a **scope** and a **subject**:

```
<type>(<scope>): <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

The **header** with **type** is mandatory. The **scope** is optional, but when present it is validated by `.github/commitlint.config.cjs` (`scope-enum`) — only the values listed under [Scope](#scope) are accepted. There is no `scope-empty: never` rule today, so commits with no scope pass commitlint; reviewers may still ask you to add one.

Subject + body lines ≤72 characters where practical; commitlint enforces `body-max-line-length: 200`. The shorter limit keeps messages readable on GitHub and in `git log`.

The footer should reference a GitHub issue using the [closing-keyword syntax](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue) (`Closes: #1234`, `Fixes: #1234`, `Resolves: #1234`) so the issue auto-closes when the PR merges.

Example 1:

```
feat(cli): add HTTP profile fullflow to activate

Allows `rpc activate --url https://console/api/v1/admin/profiles/export/...`
to fetch an encrypted profile and orchestrate activation locally instead
of relaying through RPS over wss.

Closes: #1234
```

Example 2:

```
fix(rps): preserve TLS 1.3 framing when bridging AMT WSMAN

The relay was dropping the second record in a TLS 1.3 ChangeCipherSpec
sequence, causing RPS to time out the handshake on AMT 18+ devices.

Fixes: #4567
```

### Revert

If the commit reverts a previous commit, it should begin with `revert: `, followed by the header of the reverted commit. In the body it should say: `This reverts commit <hash>.`, where the hash is the SHA of the commit being reverted.

### Type

Must be one of the following. The **semantic-release impact on `main`** (the v3 `beta` channel per `.releaserc.json`) is shown for each:

| Type | Release |
|---|---|
| **feat** | minor prerelease (`x.Y.0-beta.N`) |
| **fix** | patch (`x.y.Z-beta.N`) |
| **perf** | patch |
| **chore** | patch (configured via `releaseRules` in `.releaserc.json`) |
| **docs** | no release |
| **style** | no release (whitespace, formatting, semicolons — no code-meaning change) |
| **refactor** | no release |
| **test** | no release |
| **build** | no release (build system / CI / external deps) |
| **ci** | no release |
| **revert** | reverts a previous commit; release impact follows the reverted commit |

Any commit body containing `BREAKING CHANGE:` cuts a **major** release regardless of type. The `2.x.x` branch publishes on the `2.x` channel and `release`/tagged builds publish on the default channel — see `.releaserc.json` for the branch matrix.

### Scope

The scope is optional. When you do provide one, it is validated against `.github/commitlint.config.cjs:scope-enum` and must be one of the values below (commits with no scope still pass commitlint, but reviewers may ask you to add one):

- **lme** — Local Management Engine functionality (`internal/lm/engine*.go`)
- **lms** — Local Management Service functionality (`internal/lm/service*.go`)
- **lmx** — Changes that affect both `lme` and `lms`
- **utils** — Utility functions and shared helpers (`pkg/utils/`)
- **cli** — Kong-level CLI changes (`internal/cli/`), top-level command wiring, global flags
- **rps** — Legacy ws/wss path to Remote Provisioning Server (`internal/rps/`)
- **heci** — HECI/MEI driver bindings (`pkg/heci/`)
- **pthi** — Platform Trust Host Interface protocol (`pkg/pthi/`)
- **sample** — Sample applications (`samples/`)
- **docker** — Dockerfile / compose
- **deps** — Production dependency changes (primarily dependabot)
- **deps-dev** — Developer dependency changes (primarily dependabot)
- **gh-actions** — GitHub Actions workflows (`.github/workflows/`)
- **config** — Service configuration (`config.yaml` schema, `kong-yaml` wiring, env var contracts)
- **internal** — Catch-all for `internal/` changes that don't fit a more specific scope (e.g. `commands/`, `orchestrator/`, `profile/`, `device/`)
- **local** — Local activation/HECI integration helpers (`internal/local/`)

Pick the most specific match. Multi-area changes are usually a sign the PR should be split — see [Pull Request practices](#pull-request-practices). If the change genuinely spans many areas and the scope list doesn't fit, raise it in the PR and a reviewer can advise.

### Body

Just as in the **subject**, use the imperative, present tense: "change" not "changed" nor "changes".
Detailed guideline ([reference](https://chris.beams.io/posts/git-commit/)):

```
More detailed explanatory text, if necessary. Wrap it to about 72
characters or so. In some contexts, the first line is treated as the
subject of the commit and the rest of the text as the body. The
blank line separating the summary from the body is critical (unless
you omit the body entirely); various tools like `log`, `shortlog`
and `rebase` can get confused if you run the two together.

Explain the problem that this commit is solving. Focus on why you
are making this change as opposed to how (the code explains that).
Are there side effects or other unintuitive consequences of this
change? Here's the place to explain them.

Further paragraphs come after blank lines.

 - Bullet points are okay, too

 - Typically a hyphen or asterisk is used for the bullet, preceded
   by a single space, with blank lines in between, but conventions
   vary here
```

### Footer

The footer references the GitHub issue this commit **Closes**, **Fixes**, or **Resolves** (e.g. `Closes: #1234`). See [GitHub's closing-keyword syntax](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue) for the keywords that trigger auto-close on merge.

The footer should also contain any information about **Breaking Changes**.

**Breaking Changes** start with the word `BREAKING CHANGE:` with a space or two newlines. v3 is itself a coordinated set of breaking changes from v2 — keep `v3.0-changes.md` in sync when adding more.

## Pull Request practices

- **Keep PRs small and scoped to one concern.** A focused 50–150-line diff gets reviewed and merged quickly; a 500-line "while I was in there" diff stalls and risks regressions in unrelated activation paths. Unrelated cleanups belong in their own PRs.
- **Work in incremental phases — this is an agile team.** When a feature needs prerequisite plumbing (extracted helpers, internal API reshaping, test scaffolding), land that first as `refactor:` / `test:` / `build:` so it ships invisibly, then ship the user-visible behaviour as a single `feat:` PR that triggers the release. Each PR should leave `main` in a working state. Don't bundle prerequisites into a `feat:` commit just to save PRs — that ties the release to scaffolding that wasn't ready for users.
- **Order PRs around the semver release impact.** See the [Type table](#type). Stack `refactor:` / `test:` / `build:` ahead of the `feat:` that flips the user-visible switch.
- **PR title follows the same guidelines as the commit header** — `semantic.yml` validates it.
- **PR author is responsible for merging** after review and CI pass.
- **Preserve linear history.** PR authors choose `Rebase and merge` or `Squash and merge`, whichever fits the change.
- **Regenerate mocks when you touch an interface.** `make mock` rewrites `internal/mocks/`; commit the result in the same PR. Stale mocks are a top cause of "passes locally, fails CI."
- **Update `config.sample.yaml` / `config.yaml` when adding flags.** They're the canonical user-facing reference for the YAML surface; `kong-yaml` resolves config keys against flag `name:` tags, so a flag rename without a config update silently breaks operators.
- **Update `v3.0-changes.md`** if you introduce a v3 breaking change relative to v2 that users will hit on upgrade.
- **Update `internal/cli/testdata/fuzz/` corpora** when fixing a crash discovered by the fuzz workflow — commit the reproducer alongside the fix so the regression doesn't reappear.

## Before pushing

Recommended local checks before pushing. CI enforces equivalent behaviour (`gofmt -s` formatting check, `reviewdog/action-golangci-lint` against the same `.golangci.yml`), but binary versions aren't pinned identically — `gofumpt -extra` is a strict superset of `gofmt -s`, and the Dockerized `golangci-lint` may differ in revision from `reviewdog`'s.

```sh
# bash/zsh (Linux, macOS)
gofumpt -l -w -extra ./                                          # no diff
go vet ./...                                                     # clean
docker run --rm -v .:/app -w /app golangci/golangci-lint:latest golangci-lint run -v --fix
                                                                 # no remaining diagnostics
go test ./... -coverprofile=coverage.out -covermode=atomic       # all pass (matches CI)
make mock                                                        # only if you touched a mocked interface; commit internal/mocks/
make fuzz-regression                                             # only if you touched internal/cli/ parsing
```

On Windows PowerShell, swap `-v .:/app` for `-v ${pwd}:/app` and chain commands with `;` rather than `&&`. Everything else (Go, Docker, mockgen) runs natively — WSL is **not** required.

Install `gofumpt` once:

```sh
go install mvdan.cc/gofumpt@latest
```

For deeper architectural and implementation guidance — the Kong CLI hierarchy, the `AMTBaseCmd` lifecycle, the subprocess orchestrator model, the four activation paths, HECI/LMS/WSMAN layering, the C-shared library entry points — see [CLAUDE.md](./CLAUDE.md).
