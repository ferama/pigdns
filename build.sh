#! /bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

build() {
    local cmdname=$1; shift
    local cmdpath=$1; shift
    EXT=""
    [[ $GOOS = "windows" ]] && EXT=".exe"
    echo "Building ${GOOS} ${GOARCH}"
    CGO_ENABLED=0 go build \
        -trimpath \
        -o ./bin/$cmdname-${GOOS}-${GOARCH}${EXT} $cmdpath
}

go clean -testcache
go test ./...  -cover -race || exit 1

COMMANDS="
pigdns ./cmd/server
doh ./cmd/client
"

### pigdns
GOOS=linux GOARCH=arm64 build pigdns ./cmd/server
GOOS=linux GOARCH=amd64 build pigdns ./cmd/server
GOOS=darwin GOARCH=arm64 build pigdns ./cmd/server

### doh
GOOS=linux GOARCH=arm64 build doh ./cmd/dohcli
GOOS=linux GOARCH=amd64 build doh ./cmd/dohcli
GOOS=darwin GOARCH=arm64 build doh ./cmd/dohcli
