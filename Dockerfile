#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

FROM golang:1.25-alpine@sha256:9f7db8d8d90904f8347c1f833dea4c51f9e66d54aab87e15ba128bb03f2ac82a AS builder

RUN apk update && apk upgrade && apk add --no-cache git

WORKDIR /rpc
COPY . .

# Install go-licenses
RUN go install github.com/google/go-licenses/v2@v2.0.1

# Generate license files
RUN go-licenses save ./... --save_path=licenses --ignore github.com/alecthomas/kong-yaml

# Build rpc
RUN CGO_ENABLED=0 LDFLAGS="-s -w" GOOS=linux GOARCH=amd64 go build -o /build/rpc ./cmd/rpc/main.go

FROM scratch
LABEL license='SPDX-License-Identifier: Apache-2.0' \
      copyright='Copyright (c) Intel Corporation 2021'

COPY --from=builder /build/rpc /rpc
#go-licenses will install when ./build.sh is executed
COPY --from=builder /rpc/licenses /licenses

ENTRYPOINT ["/rpc"]
