#!/bin/sh
# Entware installer. Run with /opt/bin/sh on Keenetic (firmware /bin/sh differs).
set -eu

fail() { echo "keenProxy: $*" >&2; exit 1; }
usage() {
    echo 'Usage: install.sh [--prefix /opt] --binary PATH'
    echo 'Installs files only; preserves configuration and does not start/restart services.'
}

prefix=/opt
binary=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix|--binary)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            case "$1" in --prefix) prefix=$2 ;; --binary) binary=$2 ;; esac
            shift 2 ;;
        # Existing updater bootstraps pass this opt-out to every release installer.
        # The embedded build never installs an external TrustTunnel dependency.
        --without-trusttunnel) shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; fail "unknown argument: $1" ;;
    esac
done
case "$prefix" in /*) ;; *) fail 'prefix must be an absolute path' ;; esac
[ -n "$binary" ] && [ -f "$binary" ] && [ -x "$binary" ] || fail '--binary must name an executable KeenProxy build for this router'

# Work on the destination filesystem so replacement by rename is atomic.
mkdir -p "$prefix/bin" "$prefix/tmp"
work=$(mktemp -d "$prefix/tmp/keenproxy-install.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

# Stage all payloads before replacing existing files.
cp "$binary" "$work/keenproxy"
chmod 755 "$work/keenproxy"
mv -f "$work/keenproxy" "$prefix/bin/keenproxy"
echo "Installed into $prefix/bin. Configuration preserved. Restart KeenProxy to load the new build."
