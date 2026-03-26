#!/usr/bin/env bash

docker run --rm -v "$(pwd)":/src -w /src -e CGO_ENABLED=1 -e GOOS=linux -e GOARCH=amd64 -e GOPROXY=https://goproxy.cn,direct golang:1.24.7 sh -c "go build -v -ldflags='-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20260224 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.19 -s -w -extldflags \"-static\"' -o /src/release/SamWafLinuxAmd64 ./cmd/samwaf/main.go"

docker run --rm -v "$(pwd)":/src -w /src -e CGO_ENABLED=1 -e GOOS=linux -e GOARCH=arm64 -e GOPROXY=https://goproxy.cn,direct golang:1.24.7 sh -c "go build -v -ldflags='-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20260224 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.19 -s -w -extldflags \"-static\"' -o /src/release/SamWafLinuxArm64 ./cmd/samwaf/main.go"
