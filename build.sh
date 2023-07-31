#! /bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

build() {
    EXT=""
    [[ $GOOS = "windows" ]] && EXT=".exe"
    echo "Building ${GOOS} ${GOARCH}"
    CGO_ENABLED=0 go build \
        -trimpath \
        -o ./bin/pigdns-${GOOS}-${GOARCH}${EXT} .
}

go clean -testcache
go test ./... -v -cover -race || exit 1

### multi arch binary build
GOOS=linux GOARCH=arm64 build
GOOS=linux GOARCH=amd64 build

GOOS=darwin GOARCH=arm64 build
