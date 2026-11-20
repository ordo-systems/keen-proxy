#!/bin/sh
# Import a pinned OpenWrt userspace; netfilter runs on Docker's Linux kernel.
set -eu

rootfs=openwrt-24.10.5-armsr-armv8-rootfs.tar.gz
url=https://downloads.openwrt.org/releases/24.10.5/targets/armsr/armv8/$rootfs
sha=f8f6bba184d691365e15bf6241a3f88afe7af47fc443c6e9ee5de15e1c9d6d43
work=$(mktemp -d)
owner=keenproxy-openwrt-$(basename "$work" | tr '[:upper:]' '[:lower:]')
image=$owner:24.10.5
cleanup() {
    rc=$?
    trap - EXIT
    if [ "$(docker inspect --format '{{index .Config.Labels "keenproxy.openwrt.owner"}}' "$owner" 2>/dev/null || :)" = "$owner" ]; then
        docker rm -f "$owner" >/dev/null || rc=1
    fi
    if [ "$(docker image inspect --format '{{index .Config.Labels "keenproxy.openwrt.owner"}}' "$image" 2>/dev/null || :)" = "$owner" ]; then
        docker image rm "$image" >/dev/null || rc=1
    fi
    if ! containers=$(docker ps -aq --filter "label=keenproxy.openwrt.owner=$owner") ||
        ! images=$(docker images -q --filter "label=keenproxy.openwrt.owner=$owner") ||
        [ -n "$containers$images" ]; then
        echo "Could not verify Docker cleanup for $owner" >&2
        rc=1
    fi
    rm -f "$work/$rootfs" "$work/keenproxy" && rmdir "$work" || rc=1
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

curl -fsSL --retry 3 --max-time 90 -o "$work/$rootfs" "$url"
(cd "$work" && printf '%s  %s\n' "$sha" "$rootfs" | shasum -a 256 -c -)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$@" -o "$work/keenproxy" ./cmd/keenproxy
docker import --platform linux/arm64 --change "LABEL keenproxy.openwrt.owner=$owner" "$work/$rootfs" "$image" >/dev/null
docker run --rm --init --privileged --name "$owner" --label "keenproxy.openwrt.owner=$owner" \
    -v "$work/keenproxy:/work/keenproxy:ro" -v "$PWD/test/openwrt/smoke.sh:/work/smoke.sh:ro" \
    -v "$PWD/test/openwrt/update-guard.sh:/work/update-guard.sh:ro" \
    -v "$PWD/tools:/work/tools:ro" \
    "$image" /bin/sh /work/smoke.sh
