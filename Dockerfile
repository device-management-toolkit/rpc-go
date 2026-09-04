#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

# syntax=docker/dockerfile:1.7

# Step 1: Download dependencies
FROM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS dependencies
WORKDIR /rpc
COPY go.mod go.sum ./
RUN go mod download

# Step 2: Builder
FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder
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
