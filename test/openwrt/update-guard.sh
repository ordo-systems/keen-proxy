#!/bin/sh
# Drive the native bootstrap and procd on a real nftables forwarding path.
set -eu

opkg install ip-full ip6tables-nft
ip6tables --version | grep -F '(nf_tables)'
mkdir -p /var/run/ubus
ubusd &
for attempt in $(seq 1 10); do
    [ -S /var/run/ubus/ubus.sock ] && break
    sleep 1
done
/sbin/procd -S &
for attempt in $(seq 1 10); do
    ubus -t 1 list service 2>/dev/null | grep -qx service && break
    sleep 1
done
ubus -t 1 list service | grep -qx service

echo 1 >/proc/sys/net/ipv4/ip_forward
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
echo 1 >/proc/sys/net/ipv6/conf/all/forwarding

mkdir -p /etc/keenproxy
cat >/etc/keenproxy/config.yaml <<'YAML'
lan: {interface: kp-lan}
api: {listen: '127.0.0.1:8086', token_file: /etc/keenproxy/token}
dns: {listen: '127.0.0.1:5354', upstreams: ['udp://198.51.100.2:53']}
intercept: {mode: redirect}
YAML
cat >/usr/bin/probe-forwarding <<'SH'
#!/bin/sh
set -eu
probe() {
    host=$1
    shift
    case "$host" in
        *:*) ip netns exec lan ping6 "$@" "$host" ;;
        *) ip netns exec lan ping "$@" "$host" ;;
    esac
}
case "$1" in
    open) probe 198.51.100.2 -c 2 -W 2; probe 2001:db8:2::2 -c 2 -W 2 ;;
    blocked)
        if probe 198.51.100.2 -c 1 -W 1 >/dev/null || probe 2001:db8:2::2 -c 1 -W 1 >/dev/null; then
            touch /tmp/forwarding-leak
            exit 1
        fi
        probe 192.0.2.1 -c 1 -W 1
        probe 2001:db8:1::1 -c 1 -W 1
        ;;
esac
SH
chmod 755 /usr/bin/probe-forwarding

# The container has no external release dependency. Only the download boundary
# is substituted after installing the real userspace packages.
curl_path=$(command -v curl)
mv "$curl_path" "$curl_path.original"
cat >"$curl_path" <<'SH'
#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    case "$1" in
        https://*/releases/download/*) src=${1#*/releases/download/} ;;
        -o) shift; out=$1 ;;
    esac
    shift
done
cp "/tmp/mirror/$src" "$out"
SH
chmod 755 "$curl_path"
for tag in v1.2.3 v1.2.4 v1.2.5; do
    dir="/tmp/mirror/$tag"
    mkdir -p "$dir"
    cp /work/keenproxy "$dir/keenproxy-linux-arm64"
    {
        printf '%s\n' '#!/bin/sh /etc/rc.common' \
            'if [ "${action:-}" = start ] && [ -f /tmp/check-forwarding ]; then probe-forwarding blocked || exit 1; fi'
        tail -n +2 /work/tools/keenproxy.openwrt
    } >"$dir/keenproxy.openwrt"
    if [ "$tag" = v1.2.4 ]; then
        printf '%s\n' '#!/bin/sh' '[ "$1" = -dry-run ]' >"$dir/keenproxy-linux-arm64"
    fi
    (cd "$dir" && sha256sum keenproxy-linux-arm64 keenproxy.openwrt >SHA256SUMS)
done

install() { KEENPROXY_PLATFORM=openwrt sh /work/tools/bootstrap.sh --version "$1"; }
if ! probe-forwarding open; then
    ip -n lan -6 route get 2001:db8:2::2
    ip -n wan -6 route get 2001:db8:1::2
    ip -6 route
    ip6tables -S
    ip netns exec lan ping6 -c 2 -W 3 2001:db8:1::1 || :
    ip netns exec wan ping6 -c 2 -W 3 2001:db8:2::1 || :
    ip -n lan -6 neigh
    ip -n wan -6 neigh
    ip -6 neigh
    echo 'FAIL: OpenWrt packet test requires direct forwarding before upgrade' >&2
    exit 1
fi
install v1.2.3
touch /tmp/check-forwarding

cat >/etc/config/firewall <<'UCI'
config defaults
    option flow_offloading '1'
UCI
before=$(cat /var/run/keenproxy/startup-state)
if install v1.2.5; then
    echo 'FAIL: upgrade accepted while OpenWrt flow offloading was enabled' >&2
    exit 1
fi
test "$(cat /var/run/keenproxy/startup-state)" = "$before"
uci set 'firewall.@defaults[0].flow_offloading=0'
uci commit firewall
probe-forwarding open

if install v1.2.4; then
    echo 'FAIL: candidate unexpectedly started' >&2
    exit 1
fi
test ! -e /tmp/forwarding-leak
grep -Fxq 'current v1.2.3' /usr/share/keenproxy/release
iptables -t nat -C PREROUTING -j KEENPROXY_DNS
probe-forwarding open

install v1.2.5
test ! -e /tmp/forwarding-leak
grep -Fxq 'current v1.2.5' /usr/share/keenproxy/release
iptables -t nat -C PREROUTING -j KEENPROXY_DNS
probe-forwarding open
/etc/init.d/keenproxy stop
echo 'OpenWrt: procd update and rollback block IPv4/IPv6 forwarding and preserve LAN access'
