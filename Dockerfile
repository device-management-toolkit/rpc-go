#*********************************************************************
# * Copyright (c) Intel Corporation 2021
# * SPDX-License-Identifier: Apache-2.0
# **********************************************************************

FROM golang:1.24-alpine@sha256:b4f875e650466fa0fe62c6fd3f02517a392123eea85f1d7e69d85f780e4db1c1 as builder

RUN apk update && apk upgrade && apk add --no-cache git

WORKDIR /rpc
COPY . .

# Install go-licenses
RUN go install github.com/google/go-licenses@v1.0.0
# Generate license files
RUN go-licenses save ./... --save_path=licenses

# Build rpc
RUN CGO_ENABLED=0 LDFLAGS="-s -w" GOOS=linux GOARCH=amd64 go build -o /build/rpc ./cmd/rpc/main.go

FROM scratch
LABEL license='SPDX-License-Identifier: Apache-2.0' \
      copyright='Copyright (c) Intel Corporation 2021'

COPY --from=builder /build/rpc /rpc
#go-licenses will install when ./build.sh is executed
COPY --from=builder /rpc/licenses /licenses

ENTRYPOINT ["/rpc"]
