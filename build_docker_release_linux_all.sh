#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(pwd)"
mkdir -p "${PROJECT_DIR}/release"

echo "Building linux/amd64..."
docker run --rm \
  --platform linux/amd64 \
  -v "${PROJECT_DIR}:/src" \
  -w /src \
  -e CGO_ENABLED=1 \
  -e GOOS=linux \
  -e GOARCH=amd64 \
  -e GOPROXY=https://goproxy.cn,direct \
  golang:1.24.7 \
  sh -lc "go build -v -ldflags='-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20260224 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.19 -s -w -extldflags \"-static\"' -o /src/release/SamWafLinuxAmd64 ./cmd/samwaf/main.go"

echo "Building linux/arm64..."
docker run --rm \
  --platform linux/arm64 \
  -v "${PROJECT_DIR}:/src" \
  -w /src \
  -e CGO_ENABLED=1 \
  -e GOOS=linux \
  -e GOARCH=arm64 \
  -e GOPROXY=https://goproxy.cn,direct \
  golang:1.24.7 \
  sh -lc "go build -v -ldflags='-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20260224 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.19 -s -w -extldflags \"-static\"' -o /src/release/SamWafLinuxArm64 ./cmd/samwaf/main.go"

echo "Done. Outputs:"
echo "- release/SamWafLinuxAmd64"
echo "- release/SamWafLinuxArm64"
