#!/bin/sh
# Stage a released ARM64 baseline and a current test build for the Docker router.
set -eu

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$work/release"
base=https://github.com/ordo-systems/keen-proxy/releases/download/v0.9.2
for asset in SHA256SUMS keenproxy-linux-arm64 S99keenproxy install.sh; do
    curl -fsSL --retry 2 --max-time 120 "$base/$asset" -o "$work/release/$asset"
done
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$@" -o "$work/keenproxy" ./cmd/keenproxy

docker run --rm --init --privileged --platform linux/arm64 \
    --mount "type=bind,source=$work/keenproxy,target=/work/keenproxy,readonly" \
    --mount "type=bind,source=$work/release,target=/work/release-0.9.2,readonly" \
    --mount "type=bind,source=$PWD/tools,target=/work/tools,readonly" \
    --mount "type=bind,source=$PWD/test/entware/smoke.sh,target=/work/smoke.sh,readonly" \
    debian:bookworm-slim sh /work/smoke.sh
