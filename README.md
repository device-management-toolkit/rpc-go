# Remote Provisioning Client (RPC)

![CodeQL](https://img.shields.io/github/actions/workflow/status/device-management-toolkit/rpc-go/codeql-analysis.yml?style=for-the-badge&label=CodeQL&logo=github)
![Build](https://img.shields.io/github/actions/workflow/status/device-management-toolkit/rpc-go/main.yml?style=for-the-badge&logo=github)
![Codecov](https://img.shields.io/codecov/c/github/device-management-toolkit/rpc-go?style=for-the-badge&logo=codecov)
[![OSSF-Scorecard Score](https://img.shields.io/ossf-scorecard/github.com/device-management-toolkit/rpc-go?style=for-the-badge&label=OSSF%20Score)](https://api.securityscorecards.dev/projects/github.com/device-management-toolkit/rpc-go)
[![Discord](https://img.shields.io/discord/1063200098680582154?style=for-the-badge&label=Discord&logo=discord&logoColor=white&labelColor=%235865F2&link=https%3A%2F%2Fdiscord.gg%2FDKHeUNEWVH)](https://discord.gg/DKHeUNEWVH)
[![Docker Pulls](https://img.shields.io/docker/pulls/intel/oact-rpc-go?style=for-the-badge&logo=docker)](https://hub.docker.com/r/intel/oact-rpc-go)

> Disclaimer: Production viable releases are tagged and listed under 'Releases'. All other check-ins should be considered 'in-development' and should not be used in production

RPC is used for activation, deactivation, maintenance, and status of an AMT device
The Remote Provisioning Client (RPC) is an application that assists with activation, configuration, and maintenance of for Intel® AMT devices. RPC provides source code that must be compiled into a binary to run or library for integration with other client applications.

---

**For detailed documentation** about Getting Started or other features of the Device Management Toolkit, see the [docs](https://device-management-toolkit.github.io/docs/).

---


## Prerequisites

- [Golang](https://go.dev/dl/)

## Build

### Windows

#### As executable:

```
go build -o rpc.exe ./cmd/rpc/main.go
```

#### As Library:

```
go build -buildmode=c-shared -o rpc.dll ./cmd/rpc
```

### Linux

#### As executable:

```
go build -o rpc ./cmd/rpc/main.go
```

#### As Library:

```
CGO_ENABLED=1 go build -buildmode=c-shared -o librpc.so ./cmd/rpc
```

### Docker image

```bash
docker build -t rpc-go:latest .
```

## Run

Install the executable on a target device and then run from a terminal/shell
command line with <b>adminstrator privileges</b>.

For usage, call the executable with no additional parameters.

### Configuration file

RPC can preload defaults from a YAML configuration file (default: `config.yaml` in the working directory or passed explicitly via `--config <path>`).

See `config.sample.yaml` for a fully documented example containing every command and flag. Typical workflow:

1. Copy the sample: `cp config.sample.yaml config.yaml` (or on Windows `copy config.sample.yaml config.yaml`).
2. Edit only the sections you need (e.g. set `configure: sync-clock: password:` or activation parameters).
3. Run a command using the file:

```shell
rpc --config config.yaml configure sync-clock
```

CLI flags and environment variables always override values loaded from the file.

Sensitive values (passwords, tokens) can also be provided via environment variables (see flag `env:` tags in code) instead of storing in plaintext YAML.

#### Global AMT Password

You can now supply a single global AMT admin password once via either:

```
rpc --amt-password <pass> <command> ...
```

or environment variable:

```
set AMT_PASSWORD=<pass>   # Windows PowerShell
export AMT_PASSWORD=<pass> # Linux/macOS
```

All commands that require an AMT password will use this value automatically unless a per-command `--password` is explicitly provided (legacy behavior kept for backward compatibility). The sample config (`config.sample.yaml`) reflects this by using a top-level `amt-password:` key instead of repeating `password:` under each command section.

### Windows

```shell
.\rpc
```

### Linux

```bash
sudo ./rpc
```

### Docker

```bash
$ docker run --rm -it --device /dev/mei0 rpc-go:latest
```

<br>

# Dev tips for passing CI Checks

- Ensure code is formatted correctly with `gofumpt -l -w -extra ./`
- Ensure all unit tests pass with `go test ./...`
- Ensure code has been linted with `docker run --rm -v ${pwd}:/app -w /app golangci/golangci-lint:latest golangci-lint run -v`

## Fuzz Testing

The project includes fuzz tests to identify edge cases and potential panics in CLI command parsing. Fuzz testing uses Go's built-in fuzzing support (Go 1.18+).

### Running Fuzz Tests Locally

```bash
# Run quick fuzz tests (30 seconds per test)
make fuzz-short

# Run extended fuzz tests (5 minutes per test)
make fuzz

# Run regression tests with existing corpus only
make fuzz-regression

# Run a specific fuzz test manually
go test -fuzz=FuzzDeactivate -fuzztime=1m ./internal/cli
```

### Continuous Integration

Fuzz tests run automatically in GitHub Actions:
- **Pull Requests & Pushes**: Quick 30-second fuzz tests on each PR
- **Scheduled (Weekly)**: Extended 10-minute fuzz tests every Monday
- **Manual Trigger**: Run with custom duration via workflow_dispatch

If fuzz testing discovers a crash, the failure inputs are uploaded as artifacts for investigation.

### Seed Corpus

The project maintains seed corpus files in `internal/cli/testdata/fuzz/` to ensure effective fuzzing coverage. These files represent valid and edge-case CLI commands that the fuzzer uses as starting points.

## Additional Resources

- For detailed documentation and Getting Started, [visit the docs site](https://device-management-toolkit.github.io/docs).

- Looking to contribute? [Find more information here about contribution guidelines and practices](.\CONTRIBUTING.md).

- Find a bug? Or have ideas for new features? [Open a new Issue](https://github.com/device-management-toolkit/rpc-go/issues).

- Need additional support or want to get the latest news and events about Open AMT? Connect with the team directly through Discord.

  [![Discord Banner 1](https://discordapp.com/api/guilds/1063200098680582154/widget.png?style=banner2)](https://discord.gg/DKHeUNEWVH)
