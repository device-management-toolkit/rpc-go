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

- Ensure code is formatted correctly with `gofmt -s -w ./`
- Ensure all unit tests pass with `go test ./...`
- Ensure code has been linted with `docker run --rm -v ${pwd}:/app -w /app golangci/golangci-lint:v1.52.2 golangci-lint run -v`

## Additional Resources

- For detailed documentation and Getting Started, [visit the docs site](https://device-management-toolkit.github.io/docs).

- Looking to contribute? [Find more information here about contribution guidelines and practices](.\CONTRIBUTING.md).

- Find a bug? Or have ideas for new features? [Open a new Issue](https://github.com/device-management-toolkit/rpc-go/issues).

- Need additional support or want to get the latest news and events about Open AMT? Connect with the team directly through Discord.

  [![Discord Banner 1](https://discordapp.com/api/guilds/1063200098680582154/widget.png?style=banner2)](https://discord.gg/DKHeUNEWVH)
