#!/bin/sh
# Exercise the real Entware controller and firewall tools in a disposable router.
set -eu

[ -f /.dockerenv ] && [ -f /work/keenproxy ] && [ -f /work/release-0.9.2/SHA256SUMS ] ||
    { echo 'Run this scenario with make integration-entware' >&2; exit 1; }

apt-get -qq update
apt-get -qq install -y --no-install-recommends ca-certificates curl wget iproute2 \
    iputils-ping procps >/dev/null
mkdir -p /opt/bin /opt/etc /opt/tmp /opt/var/lock
feed=https://bin.entware.net/aarch64-k3.10
curl -fsSL "$feed/installer/opkg" -o /opt/bin/opkg
curl -fsSL "$feed/installer/opkg.conf" | sed s,http://,https://, > /opt/etc/opkg.conf
chmod 755 /opt/bin/opkg
/opt/bin/opkg update
/opt/bin/opkg install entware-opt iptables
test -x /opt/bin/sh
test -x /opt/etc/init.d/rc.unslung
for tool in iptables ip6tables; do
    "/opt/sbin/$tool" --version
    "/opt/sbin/$tool" -w -t filter -S
done

for side in lan wan; do
    ip netns add "$side"
    ip link add "kp-$side" type veth peer name eth0 netns "$side"
    ip link set "kp-$side" up
    ip -n "$side" link set eth0 up
done
ip addr add 192.0.2.1/24 dev kp-lan
ip addr add 198.51.100.1/24 dev kp-wan
ip addr add 2001:db8:1::1/64 dev kp-lan nodad
ip addr add 2001:db8:2::1/64 dev kp-wan nodad
ip -n lan addr add 192.0.2.2/24 dev eth0
ip -n wan addr add 198.51.100.2/24 dev eth0
ip -n lan addr add 2001:db8:1::2/64 dev eth0 nodad
ip -n wan addr add 2001:db8:2::2/64 dev eth0 nodad
ip -n lan route add default via 192.0.2.1
ip -n wan route add default via 198.51.100.1
ip -n lan -6 route add default via 2001:db8:1::1
ip -n wan -6 route add default via 2001:db8:2::1
echo 1 >/proc/sys/net/ipv4/ip_forward
echo 1 >/proc/sys/net/ipv6/conf/all/forwarding

mkdir -p /opt/etc/keenproxy
cat >/opt/etc/keenproxy/config.yaml <<'YAML'
lan: {interface: kp-lan}
api: {listen: '127.0.0.1:8086', token_file: /opt/etc/keenproxy/token}
dns: {listen: '127.0.0.1:5354', upstreams: ['udp://198.51.100.2:53']}
intercept: {mode: redirect}
YAML

mkdir -p /tmp/mirror
cp -R /work/release-0.9.2 /tmp/mirror/v0.9.2
for tag in v1.2.4 v1.2.5; do
    dir=/tmp/mirror/$tag
    mkdir -p "$dir"
    cp /work/keenproxy "$dir/keenproxy-linux-arm64"
    cp /work/tools/S99keenproxy /work/tools/install.sh "$dir"
    if [ "$tag" = v1.2.4 ]; then
        cat >"$dir/keenproxy-linux-arm64" <<'SH'
#!/bin/sh
case "$1" in
    -dry-run) exec /work/keenproxy "$@" ;;
    -startup-state-protocol) exec /work/keenproxy "$@" ;;
    *) touch /tmp/candidate-launched; exit 42 ;;
esac
SH
    fi
    (cd "$dir" && sha256sum keenproxy-linux-arm64 S99keenproxy install.sh >SHA256SUMS)
done

cat >/tmp/observe-bootstrap.sh <<'SH'
set -eu
probe() { ip netns exec lan ping -n -c 1 -W 1 "$1" >/dev/null; }
# Preserve the shipped bootstrap's staging and checksum checks with local assets.
curl() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            https://*/releases/download/*) src=${1#*/releases/download/} ;;
            -o) shift; out=$1 ;;
        esac
        shift
    done
    cp "/tmp/mirror/$src" "$out"
}
# Sample the stopped window before delegating to the unmodified controller.
sh() {
    if [ "$#" = 2 ] && [ "$1" = /opt/etc/init.d/S99keenproxy ] &&
        [ "$2" = start ] && [ -f /tmp/check-forwarding ]; then
        cmp -s "$1" /work/tools/S99keenproxy || return 1
        if [ -e /var/run/keenproxy/pid ] || probe 198.51.100.2 || probe 2001:db8:2::2; then
            touch /tmp/forwarding-leak
            echo 'FAIL: gap has a stale daemon or direct WAN reachability' >&2
            return 1
        fi
        probe 192.0.2.1 && probe 2001:db8:1::1 || return 1
        printf '%s\n' 'Guarded startup: WAN IPv4/IPv6 blocked, router reachable from LAN.'
        printf '%s\n' start >> /tmp/guarded-starts
    fi
    /opt/bin/sh "$@"
}
export KEENPROXY_PLATFORM=entware KEENPROXY_PREFIX=/opt
. /work/tools/bootstrap.sh
SH

install() { /opt/bin/sh /tmp/observe-bootstrap.sh --version "$1"; }
assert_ready() {
    grep -Fxq "current $1" /opt/share/keenproxy/release
    grep -Eq '^active [0-9]+$' /var/run/keenproxy/startup-state
    /opt/bin/sh /opt/etc/init.d/S99keenproxy status
    ip netns exec lan ping -n -c 2 -W 2 198.51.100.2
    ip netns exec lan ping -n -c 2 -W 2 2001:db8:2::2
}

install v0.9.2
assert_ready v0.9.2
touch /tmp/check-forwarding
if install v1.2.4; then
    echo 'FAIL: broken candidate unexpectedly started' >&2
    exit 1
fi
test -f /tmp/candidate-launched
test ! -e /tmp/forwarding-leak
test "$(wc -l </tmp/guarded-starts)" -eq 2
assert_ready v0.9.2
install v1.2.5
test ! -e /tmp/forwarding-leak
test "$(wc -l </tmp/guarded-starts)" -eq 3
assert_ready v1.2.5
/opt/bin/sh /opt/etc/init.d/S99keenproxy stop
printf '%s\n' 'PASS: Entware S99keenproxy update and rollback with real IPv4/IPv6 packets'
