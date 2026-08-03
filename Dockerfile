#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

# syntax=docker/dockerfile:1.7

# Step 1: Download dependencies
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS dependencies
WORKDIR /rpc
COPY go.mod go.sum ./
RUN go mod download

# Step 2: Builder
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
ARG TARGETARCH=amd64
ARG TARGETVARIANT
RUN apk add --no-cache git ca-certificates

WORKDIR /rpc
COPY --from=dependencies /go/pkg /go/pkg
COPY . .

# Install go-licenses
RUN go install github.com/google/go-licenses/v2@v2.0.1

# Generate license files
RUN $(go env GOPATH)/bin/go-licenses save ./... --save_path=licenses --ignore github.com/alecthomas/kong-yaml

# Build rpc with proper ldflags and cache mounts
RUN --mount=type=cache,target=/root/.cache/go-build \
        sh -c 'if [ "$TARGETARCH" = "arm" ] && [ -n "$TARGETVARIANT" ]; then \
            export GOARM=${TARGETVARIANT#v}; \
        fi; \
        CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /build/rpc ./cmd/rpc/main.go'

# Step 3: Final
FROM scratch
LABEL license='SPDX-License-Identifier: Apache-2.0' \
      copyright='Copyright (c) Intel Corporation 2021'

COPY --from=builder /build/rpc /rpc
COPY --from=builder /rpc/licenses /licenses
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ARG RPC_UID=0
ARG RPC_GID=0
USER ${RPC_UID}:${RPC_GID}
ENTRYPOINT ["/rpc"]
