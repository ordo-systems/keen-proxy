#!/bin/sh
# Manage a verified KeenProxy release on Entware or native OpenWrt.
(
set -eu
umask 077

# Consume this marker before a restarted service can inherit it.
bootstrap_retry=${KEENPROXY_BOOTSTRAP_RETRY:-0}
unset KEENPROXY_BOOTSTRAP_RETRY

fail() { printf 'KeenProxy: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage: sh -s -- [--version vX.Y.Z] [--lite] [--require-guard]' \
        '       sh -s -- --version vX.Y.Z --expect-current vX.Y.Z [--expect-variant full|lite] [--lite] [--require-guard]' \
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
release_page=https://github.com/ordo-systems/keen-proxy/releases
releases="$release_page/download"
version=
expected_current=
expected_variant=
variant=full
uninstall=0
require_guard=0
legacy_optout=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] && [ -n "$2" ] || fail 'missing --version value'; version=$2; shift ;;
        --expect-current) [ "$#" -ge 2 ] && [ -n "$2" ] || fail 'missing --expect-current value'; expected_current=$2; shift ;;
        --expect-variant) [ "$#" -ge 2 ] || fail 'missing --expect-variant value'
            case "$2" in full|lite) expected_variant=$2 ;; *) fail 'invalid expected variant' ;; esac
            shift ;;
        --lite) variant=lite ;;
        --require-guard) require_guard=1 ;;
        # Preserve the old updater/CLI input without installing a separate client.
        --without-trusttunnel) legacy_optout=1 ;;
        --uninstall) uninstall=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; fail "unknown option: $1" ;;
    esac
    shift
done
if [ "$uninstall" = 1 ] && { [ -n "$version$expected_current$expected_variant" ] || [ "$variant" = lite ] ||
    [ "$legacy_optout" = 1 ] || [ "$require_guard" = 1 ]; }; then
    fail '--uninstall cannot be combined with installation options'
fi
if [ -n "$expected_current" ] && [ -z "$version" ]; then
    fail '--expect-current requires an explicit --version'
fi
if [ -n "$expected_variant" ] && [ -z "$expected_current" ]; then
    fail '--expect-variant requires --expect-current'
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
    if command -v hexdump >/dev/null 2>&1; then
        head -c 6 /proc/self/exe | hexdump -v -e '1/1 "%02x"'
    else
        head -c 6 /proc/self/exe | od -An -v -tx1 | tr -d '[:space:]'
    fi
}

architecture() {
    cpu=$(uname -m)
    case "$cpu" in
        aarch64|arm64)
            case "$(elf_header)" in
                7f454c4602??) echo arm64 ;;
                7f454c4601??) echo armv5 ;;
                *) fail 'cannot determine ARM userspace ELF class' ;;
            esac ;;
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

checksum() {
    sum=$(sha256sum "$1") || return 1
    printf '%s\n' "${sum%% *}"
}

verify() {
    expected=$(awk -v name="$1" '$2 == name {print $1}' "$work/SHA256SUMS")
    case "$expected" in *[!0-9a-fA-F]*) fail "invalid SHA256 entry for $1" ;; esac
    [ "${#expected}" -eq 64 ] || fail "missing or invalid SHA256 entry for $1"
    [ "$(checksum "$work/$1")" = "$expected" ] || fail "SHA256 mismatch for $1"
}

# Retry only from preflight, before touching service state or installed files.
retry_release_bootstrap() {
    printf 'KeenProxy: %s\n' "$1" >&2
    [ "$bootstrap_retry" != 1 ] || exit 1
    # Older releases do not ship a separately checksummed bootstrap.
    awk '$2 == "bootstrap.sh" {found = 1} END {exit !found}' "$work/SHA256SUMS" || exit 1
    printf 'KeenProxy: retrying with the bootstrap from release %s\n' "$tag" >&2
    fetch "$base/bootstrap.sh" "$work/bootstrap.sh"
    verify bootstrap.sh
    # Free candidate space before the child downloads and stages its own files.
    rm -rf "$work/payload" || fail 'could not remove the first staged payload'
    if [ -n "$asset" ]; then
        rm -f "$work/$asset" || fail 'could not remove the first candidate binary'
    fi

    set -- --version "$tag"
    if [ -n "$expected_current" ]; then set -- "$@" --expect-current "$expected_current"; fi
    if [ -n "$expected_variant" ]; then set -- "$@" --expect-variant "$expected_variant"; fi
    if [ "$variant" = lite ]; then set -- "$@" --lite; fi
    if [ "$require_guard" = 1 ]; then set -- "$@" --require-guard; fi
    if [ "$legacy_optout" = 1 ]; then set -- "$@" --without-trusttunnel; fi
    # The fallback takes its own installer lock and revalidates installed state.
    rmdir "$lock" || fail 'could not release installer lock for fallback'
    lock=
    if KEENPROXY_BOOTSTRAP_RETRY=1 sh -s -- "$@" < "$work/bootstrap.sh"; then exit 0; fi
    if [ -n "$expected_variant" ]; then
        echo 'KeenProxy: panel fallback requires a bootstrap with --expect-variant support; retry from the LAN if the release bootstrap does not recognize it' >&2
    fi
    exit 1
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

# Each installed binary is controlled by the script installed alongside it.
service_action() {
    if [ "$platform" = openwrt ]; then
        action=$1
        if [ "$action" = check ]; then action=running; fi
        KEENPROXY_SERVICE_LOCK_TOKEN="$work" sh "$prefix/etc/rc.common" "$service" "$action"
    else
        KEENPROXY_SERVICE_LOCK_TOKEN="$work" sh "$service" "$1"
    fi
}

# Match only the installer-owned rule. FORWARD leaves access to router services
# and the replacement daemon's outbound connections available during startup.
guard_rule() {
    "$1" -w -t filter "$2" FORWARD -m comment --comment keenproxy-release-guard -j DROP
}

# Try the checksum-verified candidate first. A downgrade without this flag can
# use the installed release's snapshot. The actual guard policy still decides
# whether an update may proceed.
restore_autoload_guard() {
    [ "$platform" = entware ] || return 0
    [ -f "${config}.autoload-guard" ] && [ ! -L "${config}.autoload-guard" ] || return 0
    module_status=0
    module_output=$("$staged_binary" -autoload-update-guard -config "$config" -iptables "$guard4" 2>&1) || module_status=$?
    [ "$module_status" = 0 ] && return 0
    case "$module_status:$module_output" in
        '2:flag provided but not defined: -autoload-update-guard'*)
            if [ -x "$work/previous/$binary_path" ] &&
                "$work/previous/$binary_path" -autoload-update-guard -config "$config" -iptables "$guard4" >/dev/null 2>&1; then
                return 0
            fi ;;
    esac
    echo 'KeenProxy: warning: could not restore the saved firmware module autoload guard; continuing with the forwarding guard policy' >&2
    return 0
}

find_forwarding_guard() {
    if [ -x "$guard4" ] && guard_rule "$guard4" -C >/dev/null 2>&1; then held4=1; fi
    if [ ! -x "$guard6" ]; then
        echo 'KeenProxy: warning: ip6tables unavailable; cannot check for an existing IPv6 forwarding guard. If an old guard remains, restore ip6tables and rerun the bootstrap.' >&2
    elif guard_rule "$guard6" -C >/dev/null 2>&1; then
        held6=1
    fi
}

hold_forwarding() {
    ipv6_forwarding=0
    for control in /proc/sys/net/ipv6/conf/*/forwarding; do
        if [ -r "$control" ] && [ "$(cat "$control")" = 1 ]; then
            ipv6_forwarding=1
            break
        fi
    done
    if [ "$platform" = openwrt ]; then
        for option in flow_offloading flow_offloading_hw; do
            case "$(uci -q get "firewall.@defaults[0].$option" 2>/dev/null || :)" in
                1|on|true|yes) fail 'disable OpenWrt flow offloading and reload the firewall before updating' ;;
            esac
        done
        if nft list flowtable inet fw4 ft >/dev/null 2>&1; then
            fail 'reload the OpenWrt firewall with flow offloading disabled before updating'
        fi
    fi
    check_routing=1
    added6=0
    if [ "$ipv6_forwarding" = 1 ] && [ "$held6" = 0 ]; then
        if [ -x "$guard6" ] && guard_rule "$guard6" -I; then
            held6=1
            added6=1
        elif [ "$require_guard" = 1 ]; then
            fail 'could not block IPv6 forwarding; service left unchanged'
        else
            echo 'KeenProxy: warning: could not block IPv6 forwarding; continuing without a confirmed IPv6 guard' >&2
        fi
    fi
    if [ "$held4" = 0 ]; then
        if guard_rule "$guard4" -I; then
            held4=1
        elif [ "$require_guard" = 1 ]; then
            # Undo only the IPv6 guard installed by this attempt.
            if [ "$added6" = 1 ]; then
                release_forwarding || fail 'could not block IPv4 forwarding or remove the new IPv6 guard; service left unchanged'
            fi
            fail 'could not block IPv4 forwarding; service left unchanged'
        else
            echo 'KeenProxy: warning: could not block IPv4 forwarding; continuing without a confirmed IPv4 guard' >&2
        fi
    fi
}

release_forwarding() {
    released4=0
    if [ "$held4" = 1 ]; then
        guard_rule "$guard4" -D || return 1
        held4=0
        released4=1
    fi
    if [ "$held6" = 1 ]; then
        if ! guard_rule "$guard6" -D; then
            # A failed uninstall will restart the old service. Reblock the
            # family already released before that unprotected interval.
            if [ "${1:-}" = uninstall ] && [ "$released4" = 1 ]; then
                if guard_rule "$guard4" -I; then
                    held4=1
                else
                    echo 'KeenProxy: could not restore the IPv4 forwarding guard before uninstall rollback' >&2
                fi
            fi
            return 1
        fi
        held6=0
    fi
}

start_release() {
    service_action start || return 1
    [ "$check_routing$held4$held6" != 000 ] || return 0
    wait_for_interception "${1:-previous}"
}

wait_for_interception() {
    attempts=5
    while [ "$attempts" -gt 0 ]; do
        # Apply can restore routing without rewriting the startup marker.
        if [ "${1:-}" != running ] && [ -r "$state/startup-state" ]; then
            case "$(cat "$state/startup-state")" in 'management-only '*) break ;; esac
        fi
        # Older controllers return at the DNS jump. The daemon restores the
        # UDP chain before attaching any jumps, and attaches its jump last.
        if "$guard4" -w -t nat -C PREROUTING -j KEENPROXY_DNS >/dev/null 2>&1 &&
            "$guard4" -w -t nat -C PREROUTING -j KEENPROXY_TCP >/dev/null 2>&1; then
            if [ "${1:-}" != previous ] && [ "$planned_udp" = 0 ]; then return 0; fi
            if mangle=$("$guard4" -w -t mangle -S 2>/dev/null); then
                if printf '%s\n' "$mangle" | grep -Fxq -- '-A PREROUTING -j KEENPROXY_UDP'; then
                    return 0
                fi
                if { [ "${1:-}" = previous ] || [ "$planned_udp" = unknown ]; } &&
                    ! printf '%s\n' "$mangle" | grep -Fxq -- '-N KEENPROXY_UDP'; then
                    return 0
                fi
            fi
        fi
        attempts=$((attempts - 1))
        if [ "$attempts" -gt 0 ]; then sleep 1; fi
    done
    echo 'KeenProxy: traffic interception is not active' >&2
    return 1
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
    previous_variant=$(release_field variant)
    if [ "$previous_tag" = "$tag" ]; then
        # Panel targets are tags; switching builds of one tag is a CLI action.
        installed_variant=$previous_variant
        previous_tag=$(release_field previous)
        previous_variant=$(release_field previous_variant)
        previous_variant=${previous_variant:-$installed_variant}
    fi
    if ! valid_release_tag "$previous_tag"; then previous_tag=; fi
    mkdir -p "$work/payload/${release_record%/*}"
    printf 'current %s\nprevious %s\nvariant %s\n' "$tag" "$previous_tag" "$variant" > "$work/payload/$release_record"
    if [ -n "$previous_tag" ] && [ "$previous_variant" != "$variant" ]; then
        case "$previous_variant" in
            full|lite) printf 'previous_variant %s\n' "$previous_variant" >> "$work/payload/$release_record" ;;
        esac
    fi
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
            # Retain the original copy if a later path fails to restore.
            staged="$work/payload/$path"
            mkdir -p "${staged%/*}" && cp -p "$work/previous/$path" "$staged" &&
                mv -f "$staged" "$prefix/$path" || return 1
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
        # Free the download before recreating staged files for rollback.
        if [ -n "${asset:-}" ]; then rm -f "$work/$asset" || :; fi
        if { [ "$start_attempted" = 1 ] && ! service_action stop; } || ! restore_payload; then
            echo "KeenProxy: rollback failed; recovery files retained at $work" >&2
            keep_work=1
            result=1
        fi
    fi
    if [ "$keep_work" = 0 ] && [ "$result" -ne 0 ] && [ -f "$service" ]; then
        restore_autostart || { echo 'KeenProxy: could not restore service autostart state' >&2; result=1; }
    fi
    if [ "$restart_previous" = 1 ] && [ "$keep_work" = 0 ]; then
        if start_release; then
            release_forwarding || result=1
        else
            echo 'KeenProxy: previous service did not restore routing; check its status' >&2
        fi
    fi
    if [ "$held4$held6" != 00 ]; then
        echo 'KeenProxy: forwarding guard remains active; restore a working release from the LAN' >&2
    fi
    if [ -n "$service_lock" ]; then
        rm -f "$service_lock/owner" || :
        rmdir "$service_lock" || :
    fi
    if [ -n "$work" ] && [ "$keep_work" = 0 ]; then rm -rf "$work"; fi
    if [ -n "$lock" ]; then rmdir "$lock" || :; fi
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
    find_forwarding_guard
    if [ "$platform" = entware ]; then
        grep -Fq 'KEENPROXY_SERVICE_LOCK_TOKEN' "$service" || fail 'init script does not support installer locking; no files removed'
    fi
    for path in $payload; do backup_file "$path"; done
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
    release_forwarding uninstall || fail 'could not release forwarding guard'
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
start_attempted=0
was_running=0
restart_previous=0
autostart_saved=0
was_enabled=0
guard4="$prefix/$firewall_path/iptables"
guard6="$prefix/$firewall_path/ip6tables"
held4=0
held6=0
check_routing=0
planned_udp=unknown
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
    if [ -n "$expected_variant" ]; then
        [ "$(release_field variant)" = "$expected_variant" ] || fail 'installed variant changed or is not recorded'
    fi
fi

for tool in curl sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing dependency: $tool"
done
if [ -f "$prefix/etc/ssl/certs/ca-certificates.crt" ]; then
    export CURL_CA_BUNDLE="$prefix/etc/ssl/certs/ca-certificates.crt"
fi
if [ -z "$version" ]; then
    latest=$(curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 20 \
        --max-time 30 --retry 2 "$release_page/latest" -o /dev/null -w '%{url_effective}') ||
        fail 'could not find the latest published release'
    case "$latest" in
        "$release_page/tag/"*) version=${latest#"$release_page/tag/"} ;;
        *) fail 'unexpected latest release URL' ;;
    esac
    printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' ||
        fail 'latest release is not a stable version'
fi
tag="v${version#v}"
valid_release_tag "$tag" || fail 'invalid release version'
base="$releases/$tag"
fetch "$base/SHA256SUMS" "$work/SHA256SUMS"
asset=
arch=$(architecture) || retry_release_bootstrap 'could not select the release architecture'
asset="keenproxy-linux-$arch"
if [ "$variant" = lite ]; then asset="keenproxy-lite-linux-$arch"; fi
names="$asset $controller"
if [ "$platform" = entware ]; then names="$names install.sh"; fi
for name in $names; do
    fetch "$base/$name" "$work/$name"
    verify "$name"
    case "$name" in
        "$asset") binary_sha=$expected ;;
        "$controller") controller_sha=$expected ;;
    esac
done
grep -Fxq "$marker" "$work/$controller" || retry_release_bootstrap 'release controller is not managed by this installer'

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
candidate_plan() {
    # Dry-run can print credentials. Only retain whether UDP is planned.
    { "$1" -dry-run -config "$2" 2>/dev/null && printf '\n# KeenProxy validation complete\n'; } |
        awk '
            $0 == "# jumps" { jumps = 1 }
            jumps && /^iptables[[:space:]].*[[:space:]]-j[[:space:]]+KEENPROXY_UDP[[:space:]]*$/ { udp = 1 }
            END {
                if ($0 != "# KeenProxy validation complete") exit 1
                if (jumps) print udp + 0
                else print "unknown"
            }'
}

refresh_candidate_plan() {
    # A concurrent Apply may have changed the config before the old daemon stopped.
    current_sha=$(checksum "$config") || return 1
    if [ "$current_sha" != "$config_sha" ]; then
        planned_udp=$(candidate_plan "$staged_binary" "$config") || return 1
    fi
}

config_sha=$(checksum "$config_source") || fail 'could not read configuration for validation'
planned_udp=$(candidate_plan "$work/$asset" "$config_source") ||
    retry_release_bootstrap 'candidate binary or configuration failed validation'

if [ -e "$service" ] || [ -L "$service" ]; then
    managed_service || fail 'existing init script is not managed by this installer'
fi

if [ "$platform" = entware ]; then
    # Historical release installers default to fetching the external client.
    sh "$work/install.sh" --prefix "$work/payload" --binary "$work/$asset" --without-trusttunnel ||
        retry_release_bootstrap 'could not stage release files'
else
    mkdir -p "$work/payload/${binary_path%/*}"
    cp "$work/$asset" "$work/payload/$binary_path"
    chmod 755 "$work/payload/$binary_path"
fi
staged_binary="$work/payload/$binary_path"
[ -f "$staged_binary" ] && [ ! -L "$staged_binary" ] && [ -x "$staged_binary" ] ||
    retry_release_bootstrap 'installer did not stage an executable binary'
[ "$(checksum "$staged_binary")" = "$binary_sha" ] || fail 'staged binary differs from the verified release'
mkdir -p "$work/payload/etc/init.d"
chmod 755 "$work/$controller"
cp -p "$work/$controller" "$work/payload/$service_path"
[ "$(checksum "$work/payload/$service_path")" = "$controller_sha" ] ||
    fail 'staged controller differs from the verified release'

ensure_firewall_tools
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
if [ -f "$service" ]; then
    # A previous failed transaction may have deliberately left these rules in place.
    # Same-version healthy reruns stay no-ops and do not touch autoload.
    guard_needed=0
    if [ "$changed" = 1 ] || [ "$was_running" = 0 ]; then guard_needed=1; fi
    if [ "$guard_needed" = 1 ]; then restore_autoload_guard; fi
    find_forwarding_guard
    if [ "$guard_needed" = 1 ]; then hold_forwarding; fi
fi
if [ "$changed" = 1 ] && [ "$was_running" = 1 ]; then
    restart_previous=1
    service_action stop || fail 'previous service did not stop cleanly'
fi
refresh_candidate_plan || fail 'configuration changed and failed candidate validation'
if [ "$changed" = 1 ]; then
    replacing=1
    install_payload || fail 'could not install staged files'
    start_attempted=1
    start_release candidate || fail 'new service failed to start with routing'
    if [ "$platform" = openwrt ] && [ "$autostart_saved" = 0 ]; then
        service_action enable || fail 'could not enable service autostart'
    fi
    restart_previous=0
    replacing=0
elif [ "$was_running" = 0 ]; then
    start_release candidate || fail 'service failed to start with routing'
else
    wait_for_interception running || fail 'running service does not have active routing'
fi
release_forwarding || fail 'could not release forwarding guard'
printf 'KeenProxy %s (%s) installed. Configuration: %s\n' "$tag" "$asset" "$config"
print_panel_access
)
