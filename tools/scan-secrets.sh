#!/bin/sh
# Scan the current Git checkout for leaked credentials.
#
# history: every commit reachable from HEAD, including changes that exist
# only in a merge commit. A bare gitleaks detect also walks other branches,
# so the main-branch check pins the scan to HEAD.
# range <base-sha> <head-sha>: commits reachable from head but not from base.
# Both endpoints must already be commits. An unresolved revision is a
# failure, not a clean scan. A range with no commits still succeeds.
#
# The binary is the MIT-licensed gitleaks release, not gitleaks-action.
# That Action requires a license for organization repositories and scans
# only the first 30 commits of a pull request. GITLEAKS_BIN skips the pin
# and is for tests only; CI must not set it.
set -eu

version=8.30.1

usage() {
    echo "usage: scan-secrets.sh history | range <base-sha> <head-sha>" >&2
    exit 2
}

is_sha() {
    printf '%s' "$1" | grep -Eq '^[0-9a-f]{40}$'
}

# Peel to a commit so a missing object or a non-commit does not scan as clean.
require_commit() {
    if ! git rev-parse --verify --end-of-options "$1^{commit}" >/dev/null 2>&1; then
        echo "scan-secrets: not a commit: $1" >&2
        exit 2
    fi
}

# Checksums are from the v8.30.1 release checksums file.
asset_for_platform() {
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)
            asset=linux_x64
            sum=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
            ;;
        Linux-aarch64|Linux-arm64)
            asset=linux_arm64
            sum=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
            ;;
        Darwin-arm64)
            asset=darwin_arm64
            sum=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5
            ;;
        Darwin-x86_64)
            asset=darwin_x64
            sum=dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709
            ;;
        *)
            echo "unsupported platform: $(uname -s)-$(uname -m)" >&2
            exit 2
            ;;
    esac
}

install_gitleaks() {
    asset_for_platform
    download_dir=$(mktemp -d)
    archive="$download_dir/gitleaks.tar.gz"
    url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${asset}.tar.gz"
    curl -fsSL -o "$archive" "$url"
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$sum  $archive" | sha256sum -c - >/dev/null
    else
        echo "$sum  $archive" | shasum -a 256 -c - >/dev/null
    fi
    tar -xzf "$archive" -C "$download_dir" gitleaks
    chmod +x "$download_dir/gitleaks"
    gitleaks_bin=$download_dir/gitleaks
}

mode=${1:-}
case "$mode" in
    history)
        [ "$#" -eq 1 ] || usage
        require_commit HEAD
        # git log omits merge patches unless asked. first-parent keeps the
        # revision scope and includes conflict-resolution changes.
        log_opts='--diff-merges=first-parent HEAD'
        ;;
    range)
        [ "$#" -eq 3 ] || usage
        if ! is_sha "$2" || ! is_sha "$3"; then
            usage
        fi
        require_commit "$2"
        require_commit "$3"
        log_opts="--diff-merges=first-parent $2..$3"
        ;;
    *)
        usage
        ;;
esac

gitleaks_bin=${GITLEAKS_BIN:-}
download_dir=
# shellcheck disable=SC2329 # invoked by the EXIT trap, including after a failed download
cleanup() {
    if [ -n "${download_dir:-}" ]; then
        rm -rf "$download_dir"
    fi
}
trap cleanup EXIT
if [ -z "$gitleaks_bin" ]; then
    install_gitleaks
fi

set +e
"$gitleaks_bin" detect --source . --redact --verbose --no-banner --log-opts="$log_opts"
scan_status=$?
set -e
exit "$scan_status"
