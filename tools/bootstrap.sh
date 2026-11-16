#!/bin/sh
# Manage a verified KeenProxy release on Entware or native OpenWrt.
(
set -eu
umask 077

fail() { printf 'KeenProxy: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage: sh -s -- [--version vX.Y.Z] [--lite]' \
        '       sh -s -- --version vX.Y.Z --expect-current vX.Y.Z [--lite]' \
        '       sh -s -- --uninstall'
}

platform=${KEENPROXY_PLATFORM:-}
if [ -z "$platform" ]; then
    entware_root=${KEENPROXY_PREFIX:-/opt}
    native_root=${KEENPROXY_PREFIX:-/}
    if [ -f "$entware_root/etc/init.d/S99keenproxy" ] &&
        [ ! -L "$entware_root/etc/init.d/S99keenproxy" ] &&
        grep -Fxq '# KeenProxy Entware service' "$entware_root/etc/init.d/S99keenproxy"; then
        platform=entware
    elif [ -f "$native_root/etc/openwrt_release" ]; then
        platform=openwrt
    else
        platform=entware
    fi
fi
case "$platform" in
    entware)
        prefix=${KEENPROXY_PREFIX:-/opt}
        binary_path=bin/keenproxy
        service_path=etc/init.d/S99keenproxy
        controller=S99keenproxy
        release_record=share/keenproxy/release
        firewall_path=sbin
        marker='# KeenProxy Entware service' ;;
    openwrt)
        prefix=${KEENPROXY_PREFIX:-/}
        binary_path=usr/bin/keenproxy
        service_path=etc/init.d/keenproxy
        controller=keenproxy.openwrt
        release_record=usr/share/keenproxy/release
        firewall_path=usr/sbin
        marker='# KeenProxy OpenWrt service' ;;
    *) fail 'unknown KEENPROXY_PLATFORM; use openwrt or entware' ;;
esac
prefix=${prefix%/}
if [ -z "$prefix" ]; then prefix=/; fi
export KEENPROXY_PREFIX="$prefix" KEENPROXY_PLATFORM="$platform"
if [ "$platform" = openwrt ]; then
    PATH="$prefix/usr/bin:$prefix/usr/sbin:$prefix/bin:$prefix/sbin:$PATH"
else
    PATH="$prefix/bin:$prefix/sbin:$PATH"
fi
export PATH
main=https://raw.githubusercontent.com/ordo-systems/keen-proxy/main
releases=https://github.com/ordo-systems/keen-proxy/releases/download
version=
expected_current=
variant=full
uninstall=0
legacy_optout=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] && [ -n "$2" ] || fail 'missing --version value'; version=$2; shift ;;
        --expect-current) [ "$#" -ge 2 ] && [ -n "$2" ] || fail 'missing --expect-current value'; expected_current=$2; shift ;;
        --lite) variant=lite ;;
        # Preserve the old updater/CLI input without installing a separate client.
        --without-trusttunnel) legacy_optout=1 ;;
        --uninstall) uninstall=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; fail "unknown option: $1" ;;
    esac
    shift
done
if [ "$uninstall" = 1 ] && { [ -n "$version$expected_current" ] || [ "$variant" = lite ] || [ "$legacy_optout" = 1 ]; }; then
    fail '--uninstall cannot be combined with installation options'
fi
if [ -n "$expected_current" ] && [ -z "$version" ]; then
    fail '--expect-current requires an explicit --version'
fi

case "$prefix" in /*) ;; *) fail 'installation prefix must be absolute' ;; esac
if [ "$platform" = openwrt ]; then
    for path in etc/openwrt_release sbin/procd etc/rc.common; do
        [ ! -L "$prefix/$path" ] || fail "unsupported symlink prerequisite: $path"
    done
    [ -f "$prefix/etc/openwrt_release" ] &&
        [ -f "$prefix/sbin/procd" ] && [ -x "$prefix/sbin/procd" ] &&
        [ -f "$prefix/etc/rc.common" ] && [ -x "$prefix/etc/rc.common" ] ||
        fail 'native OpenWrt requires openwrt_release, procd and rc.common'
    grep -Fxq -e "DISTRIB_ID='OpenWrt'" -e 'DISTRIB_ID="OpenWrt"' "$prefix/etc/openwrt_release" ||
        fail 'native installation requires OpenWrt'
else
    [ -x "$prefix/etc/init.d/rc.unslung" ] || fail 'install Entware before running this script'
fi
if { [ "$prefix" = /opt ] || [ "$prefix" = / ]; } && [ "$(id -u)" != 0 ]; then
    fail 'run this script as root'
fi
command -v pidof >/dev/null 2>&1 || fail 'missing dependency: pidof'

elf_header() {
    head -c 6 /proc/self/exe | hexdump -v -e '1/1 "%02x"'
}

architecture() {
    cpu=$(uname -m)
    case "$cpu" in
        aarch64|arm64) echo arm64 ;;
        armv[5-8]*|arm) echo armv5 ;;
        x86_64|amd64)
            case "$(elf_header)" in
                7f454c4602??) echo amd64; return ;;
                7f454c4601??) ;;
                *) fail 'cannot determine x86 userspace ELF class' ;;
            esac
            grep -Eq '(^|[[:space:]])sse2([[:space:]]|$)' /proc/cpuinfo ||
                fail '32-bit x86 requires SSE2'
            echo 386 ;;
        i386|i486|i586|i686)
            grep -Eq '(^|[[:space:]])sse2([[:space:]]|$)' /proc/cpuinfo ||
                fail '32-bit x86 requires SSE2'
            echo 386 ;;
        mipsel|mipsle) echo mipsle ;;
        mips|mipsbe)
            case "$(elf_header)" in
                7f454c46??01) echo mipsle ;;
                7f454c46??02) echo mipsbe ;;
                *) fail 'cannot determine MIPS ELF byte order' ;;
            esac ;;
        *) fail "unsupported CPU: $cpu" ;;
    esac
}

fetch() {
    curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 20 \
        --max-time 240 --retry 2 "$1" -o "$2" || fail "download failed: $1"
}

verify() {
    expected=$(awk -v name="$1" '$2 == name {print $1}' "$work/SHA256SUMS")
    case "$expected" in *[!0-9a-fA-F]*) fail "invalid SHA256 entry for $1" ;; esac
    [ "${#expected}" -eq 64 ] || fail "missing or invalid SHA256 entry for $1"
    actual=$(sha256sum "$work/$1")
    [ "${actual%% *}" = "$expected" ] || fail "SHA256 mismatch for $1"
}

ensure_firewall_tools() {
    if [ "$platform" = openwrt ]; then
        [ -x "$prefix/$firewall_path/iptables" ] &&
            [ -x "$prefix/$firewall_path/iptables-restore" ] ||
            fail 'native iptables tools are missing; install iptables and iptables-mod-nat'
    elif [ ! -x "$prefix/sbin/iptables" ] || [ ! -x "$prefix/sbin/iptables-restore" ]; then
        [ -x "$prefix/bin/opkg" ] || fail 'opkg is required to install iptables'
        "$prefix/bin/opkg" update && "$prefix/bin/opkg" install iptables || fail 'cannot install Entware iptables'
    fi
    [ -x "$prefix/$firewall_path/iptables" ] && [ -x "$prefix/$firewall_path/iptables-restore" ] || fail 'iptables tools are missing'
    "$prefix/$firewall_path/iptables" -t nat -S >/dev/null || fail 'IPv4 NAT unavailable; check the firmware Netfilter component'
}

lock_service() {
    state="$prefix/var/run/keenproxy"
    if [ "$prefix" = /opt ]; then state=/var/run/keenproxy; fi
    mkdir -p "$state"
    mkdir "$state/action.lock" 2>/dev/null || fail 'service action already in progress'
    service_lock="$state/action.lock"
    printf '%s\n' "$work" > "$service_lock/owner"
}

# Entware can run its staged controller; rc.common requires the installed name.
service_action() {
    if [ "$platform" = openwrt ]; then
        action=$1
        if [ "$action" = check ]; then action=running; fi
        KEENPROXY_SERVICE_LOCK_TOKEN="$work" sh "$prefix/etc/rc.common" "$service" "$action"
    else
        KEENPROXY_SERVICE_LOCK_TOKEN="$work" sh "$work/S99keenproxy" "$1"
    fi
}

managed_service() {
    [ -f "$service" ] && [ ! -L "$service" ] && grep -Fxq "$marker" "$service"
}

valid_release_tag() {
    case "$1" in ''|*[!0-9A-Za-z.-]*) return 1 ;; esac
    printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$'
}

release_field() {
    [ -f "$prefix/$release_record" ] && [ ! -L "$prefix/$release_record" ] || return 0
    awk -v field="$1" '$1 == field && NF == 2 {print $2}' "$prefix/$release_record"
}

# The installer lock protects the history read and the staged record moves with the binary.
stage_release_record() {
    previous_tag=$(release_field current)
    if [ "$previous_tag" = "$tag" ]; then
        previous_tag=$(release_field previous)
    fi
    if ! valid_release_tag "$previous_tag"; then previous_tag=; fi
    mkdir -p "$work/payload/${release_record%/*}"
    printf 'current %s\nprevious %s\nvariant %s\n' "$tag" "$previous_tag" "$variant" > "$work/payload/$release_record"
}

backup_file() {
    if [ -e "$prefix/$1" ] || [ -L "$prefix/$1" ]; then
        [ -f "$prefix/$1" ] && [ ! -L "$prefix/$1" ] || fail "unsupported destination: $1"
        mkdir -p "$work/previous/${1%/*}"
        cp -p "$prefix/$1" "$work/previous/$1"
    fi
}

install_payload() {
    for path in $payload; do
        mkdir -p "$prefix/${path%/*}" || return 1
        mv -f "$work/payload/$path" "$prefix/$path" || return 1
    done
}

restore_payload() {
    for path in $payload; do
        if [ -f "$work/previous/$path" ]; then
            mv -f "$work/previous/$path" "$prefix/$path" || return 1
        else
            rm -f "$prefix/$path" || return 1
        fi
    done
}

# Quote one shell word so a copy-pasted command keeps spaces and quotes.
shell_quote() {
    printf '%s\n' "$1" | awk 'BEGIN { q = sprintf("%c", 39) } {
        gsub(q, q "\"" q "\"" q)
        printf "%s%s%s", q, $0, q
    }'
}

# The installed binary discovers the panel URL. A missing flag, empty result, or
# undiscoverable interface must not undo the install or reveal command stderr.
print_panel_access() {
    url_status=0
    url=$("$prefix/$binary_path" --url -config "$config" 2>/dev/null) || url_status=$?
    if [ "$url_status" -eq 0 ]; then
        case "$url" in
            http://?*) ;;
            *) url_status=1 ;;
        esac
    fi
    if [ "$url_status" -eq 0 ]; then
        case "$url" in
            *[[:space:]]*) url_status=1 ;;
        esac
    fi
    if [ "$url_status" -eq 0 ]; then
        printf 'Access URL: %s\n' "$url"
    else
        printf 'KeenProxy: could not determine the panel access URL; installation kept\n' >&2
        url=
    fi
    printf 'Retrieve existing panel token: %s --key -config %s\n' \
        "$(shell_quote "$prefix/$binary_path")" \
        "$(shell_quote "$config")"
    return 0
}

restore_autostart() {
    [ "$platform" = openwrt ] && [ "$autostart_saved" = 1 ] || return 0
    if [ "$was_enabled" = 1 ]; then service_action enable; else service_action disable; fi
}

save_autostart() {
    [ "$platform" = openwrt ] || return 0
    autostart_saved=1
    if service_action enabled; then was_enabled=1; fi
}

finish() {
    result=$?
    trap - EXIT
    keep_work=0
    if [ "$replacing" = 1 ]; then
        echo 'KeenProxy: restoring the previous installation' >&2
        if [ "$platform" = openwrt ] && [ "$autostart_saved" = 0 ] && [ -f "$service" ]; then
            service_action disable || { keep_work=1; result=1; }
        fi
        if { [ "$uninstall" = 0 ] && [ -f "$service" ] && ! service_action stop; } || ! restore_payload; then
            echo "KeenProxy: rollback failed; recovery files retained at $work" >&2
            keep_work=1
            result=1
        fi
    fi
    if [ "$keep_work" = 0 ] && [ "$result" -ne 0 ] && [ -f "$service" ]; then
        restore_autostart || { echo 'KeenProxy: could not restore service autostart state' >&2; result=1; }
    fi
    if [ "$restart_previous" = 1 ] && [ "$keep_work" = 0 ]; then
        service_action start || echo 'KeenProxy: previous service did not restart; check its status' >&2
    fi
    if [ -n "$service_lock" ]; then
        rm -f "$service_lock/owner" || :
        rmdir "$service_lock" || :
    fi
    if [ -n "$work" ] && [ "$keep_work" = 0 ]; then rm -rf "$work"; fi
    rmdir "$lock" || :
    exit "$result"
}

# The v1 marker is also used by the daemon to recognize stale owned hooks.
owned_netfilter_hook() {
    [ -f "$1" ] && [ ! -L "$1" ] && {
        IFS= read -r hook_shebang && [ "$hook_shebang" = '#!/bin/sh' ] &&
        IFS= read -r hook_marker && [ "$hook_marker" = '# keenproxy-netfilter-hook-v1' ]
    } < "$1"
}

uninstall_release() {
    lock_service
    hook=etc/ndm/netfilter.d/99-keenproxy.sh
    if [ ! -e "$service" ] && [ ! -L "$service" ] &&
        [ ! -e "$prefix/$binary_path" ] && [ ! -L "$prefix/$binary_path" ]; then
        if owned_netfilter_hook "$prefix/$hook"; then
            if pidof keenproxy >/dev/null 2>&1; then
                fail 'unmanaged process is running; no files removed'
            fi
            rm -f "$prefix/$hook" || fail "could not remove $hook"
        fi
        echo 'KeenProxy: no managed installation found'
        return
    fi
    managed_service || fail 'unmanaged installation; no files removed'
    if [ "$platform" = entware ]; then
        grep -Fq 'KEENPROXY_SERVICE_LOCK_TOKEN' "$service" || fail 'init script does not support installer locking; no files removed'
    fi
    for path in $payload; do backup_file "$path"; done
    if [ "$platform" = entware ]; then cp -p "$work/previous/$service_path" "$work/S99keenproxy"; fi
    save_autostart
    if service_action check; then
        restart_previous=1
        service_action stop || fail 'service did not stop cleanly; no files removed'
    elif pidof keenproxy >/dev/null 2>&1; then
        fail 'unmanaged process is running; no files removed'
    fi
    # Clean shutdown normally removed the hook. Include any owned leftover in
    # the transaction so uninstall rollback also restores it.
    if owned_netfilter_hook "$prefix/$hook"; then
        backup_file "$hook"
        payload="$payload $hook"
    fi
    if [ "$platform" = openwrt ]; then service_action disable || fail 'could not disable service autostart'; fi
    replacing=1
    for path in $payload; do rm -f "$prefix/$path" || fail "could not remove $path"; done
    replacing=0
    restart_previous=0
    printf 'KeenProxy uninstalled. Settings retained in %s/etc/keenproxy\n' "$prefix"
}

service="$prefix/$service_path"
payload="$binary_path $service_path $release_record"
# Reject linked ancestors too: an isolated root must never redirect writes.
for path in $payload etc/keenproxy/config.yaml; do
    parent=$path
    while [ "$parent" != . ]; do
        [ ! -L "$prefix/$parent" ] || fail "unsupported symlink destination: $parent"
        case "$parent" in */*) parent=${parent%/*} ;; *) parent=. ;; esac
    done
done
if [ -e "$service" ] || [ -L "$service" ]; then
    managed_service || fail 'existing init script is not managed by this installer'
fi
mkdir -p "$prefix/tmp" "$prefix/var/lock"
lock="$prefix/var/lock/keenproxy-install.lock"
mkdir "$lock" 2>/dev/null || fail 'another installer is active or an interrupted run left a lock'
work=
service_lock=
replacing=0
was_running=0
restart_previous=0
autostart_saved=0
was_enabled=0
trap finish EXIT
trap 'exit 1' HUP INT TERM
if [ "$platform" = openwrt ]; then
    mkdir -p "$prefix/usr/share/keenproxy"
    work=$(mktemp -d "$prefix/usr/share/keenproxy/keenproxy-release.XXXXXX")
else
    work=$(mktemp -d "$prefix/tmp/keenproxy-release.XXXXXX")
fi
if [ "$uninstall" = 1 ]; then
    uninstall_release
    exit 0
fi
if [ -n "$expected_current" ]; then
    valid_release_tag "$expected_current" || fail 'invalid expected release version'
    [ "$(release_field current)" = "$expected_current" ] || fail 'installed release changed or is not recorded'
fi

for tool in curl sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing dependency: $tool"
done
arch=$(architecture)
asset="keenproxy-linux-$arch"
if [ "$variant" = lite ]; then asset="keenproxy-lite-linux-$arch"; fi
if [ -f "$prefix/etc/ssl/certs/ca-certificates.crt" ]; then
    export CURL_CA_BUNDLE="$prefix/etc/ssl/certs/ca-certificates.crt"
fi
if [ -z "$version" ]; then
    fetch "$main/version.txt" "$work/version.txt"
    version=$(cat "$work/version.txt")
fi
tag="v${version#v}"
valid_release_tag "$tag" || fail 'invalid release version'
base="$releases/$tag"
fetch "$base/SHA256SUMS" "$work/SHA256SUMS"
names="$asset $controller"
if [ "$platform" = entware ]; then names="$names install.sh"; fi
for name in $names; do
    fetch "$base/$name" "$work/$name"
    verify "$name"
done
if [ "$platform" = openwrt ]; then
    grep -Fxq "$marker" "$work/$controller" || fail 'native controller is not managed by this installer'
fi

config="$prefix/etc/keenproxy/config.yaml"
config_source="$config"
if [ ! -f "$config" ]; then
    if [ "$platform" = openwrt ]; then
        printf 'schema_version: 1\napi:\n  token_file: %s/etc/keenproxy/token\nlan:\n  interface: br-lan\n' "${prefix%/}" > "$work/config.yaml"
    else
        printf 'schema_version: 1\n' > "$work/config.yaml"
    fi
    config_source="$work/config.yaml"
fi
chmod 755 "$work/$asset"
# Dry-run output can contain connection credentials. Keep it off the console.
"$work/$asset" -dry-run -config "$config_source" >/dev/null 2>&1 || fail 'candidate binary or configuration failed validation'

if [ -e "$service" ] || [ -L "$service" ]; then
    managed_service || fail 'existing init script is not managed by this installer'
fi
ensure_firewall_tools

if [ "$platform" = entware ]; then
    # Historical release installers default to fetching the external client.
    set -- --prefix "$work/payload" --binary "$work/$asset" --without-trusttunnel
    sh "$work/install.sh" "$@" || fail 'could not stage release files'
else
    mkdir -p "$work/payload/${binary_path%/*}"
    cp "$work/$asset" "$work/payload/$binary_path"
    chmod 755 "$work/payload/$binary_path"
fi
mkdir -p "$work/payload/etc/init.d"
chmod 755 "$work/$controller"
cp -p "$work/$controller" "$work/payload/$service_path"

lock_service
if [ -f "$service" ]; then save_autostart; fi
if [ -f "$service" ] && service_action check; then was_running=1; fi
if [ "$was_running" = 0 ] && pidof keenproxy >/dev/null 2>&1; then
    fail 'stop the existing unmanaged KeenProxy process before installing'
fi
stage_release_record
changed=0
for path in $payload; do
    backup_file "$path"
    if ! cmp -s "$work/payload/$path" "$prefix/$path"; then changed=1; fi
    case "$path" in
        bin/*|usr/bin/*|etc/init.d/*) if [ ! -x "$prefix/$path" ]; then changed=1; fi ;;
    esac
done
if [ "$config_source" != "$config" ]; then
    mkdir -p "${config%/*}"
    # Avoid overwriting a configuration created while the release was downloading.
    (set -C; cat "$config_source" > "$config") || fail 'could not create initial configuration'
fi
if [ "$changed" = 1 ]; then
    if [ "$was_running" = 1 ]; then
        restart_previous=1
        service_action stop || fail 'previous service did not stop cleanly'
    fi
    replacing=1
    install_payload || fail 'could not install staged files'
    service_action start || fail 'new service failed to start'
    if [ "$platform" = openwrt ] && [ "$autostart_saved" = 0 ]; then
        service_action enable || fail 'could not enable service autostart'
    fi
    restart_previous=0
    replacing=0
elif [ "$was_running" = 0 ]; then
    service_action start || fail 'service failed to start'
fi
printf 'KeenProxy %s (%s) installed. Configuration: %s\n' "$tag" "$asset" "$config"
print_panel_access
)
