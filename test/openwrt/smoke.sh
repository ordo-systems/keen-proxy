#!/bin/sh
set -eu

mkdir -p /var/lock
opkg update
opkg install iptables-nft iptables-mod-tproxy curl
iptables --version | grep -F '(nf_tables)'

cat >/tmp/config.yaml <<'YAML'
lan: {interface: eth0}
api: {listen: '127.0.0.1:8086', token_file: /tmp/token}
dns: {listen: '127.0.0.1:5354', upstreams: ['udp://192.0.2.53:53']}
intercept: {mode: tproxy}
networks:
  - {name: LAN, cidr: 192.0.2.0/24, mode: split}
YAML
umask 077
cat /proc/sys/kernel/random/uuid >/tmp/token
IFS= read -r token </tmp/token
cleanup() {
    rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ]; then cat /tmp/daemon.log >&2; fi
    if [ -n "${pid:-}" ]; then
        kill "$pid" 2>/dev/null || :
        wait "$pid" || :
    fi
    exit "$rc"
}
trap cleanup EXIT
/work/keenproxy -config /tmp/config.yaml -rule-sets /tmp/rules \
    -iptables "$(command -v iptables)" -iptables-restore "$(command -v iptables-restore)" >/tmp/daemon.log 2>&1 &
pid=$!

api() { curl -fsS --max-time 5 -H "Authorization: Bearer $token" "$@"; }
base=http://127.0.0.1:8086/api
for i in $(seq 1 30); do
    if api "$base/config" >/tmp/tproxy.json 2>/dev/null; then break; fi
    kill -0 "$pid"
    sleep 1
done
assert_active() {
    status=$(api "$base/status")
    printf '%s\n' "$status" | grep -Eq '"mode"[[:space:]]*:[[:space:]]*"'"$1"'"'
    printf '%s\n' "$status" | grep -Eq '"firewall"[[:space:]]*:[[:space:]]*true'
}
assert_tproxy_rule() {
    rules=$(iptables -w -t mangle -S PREROUTING)
    printf '%s\n' "$rules" | grep -Fx -- '-A PREROUTING -j KEENPROXY_UDP'
    rules=$(iptables -w -t mangle -S KEENPROXY_UDP)
    printf '%s\n' "$rules" | grep -qF -- ' -j TPROXY '
}
apply() { api -X PUT -H 'Content-Type: application/json' --data-binary "@$1" "$base/config" >/dev/null; }

# The legacy IPv4 inventory is not authoritative for this backend.
readiness=$(api "$base/diagnostics/tproxy")
printf 'TPROXY readiness: %s\n' "$readiness"
printf '%s\n' "$readiness" | grep -Eq '"state"[[:space:]]*:[[:space:]]*"unknown"'
assert_active tproxy
assert_tproxy_rule
sed 's/"mode"[[:space:]]*:[[:space:]]*"tproxy"/"mode":"redirect"/' /tmp/tproxy.json >/tmp/redirect.json
apply /tmp/redirect.json
assert_active redirect
rules=$(iptables -w -t mangle -S PREROUTING)
if printf '%s\n' "$rules" | grep -qFx -- '-A PREROUTING -j KEENPROXY_UDP'; then
    echo 'REDIRECT left the TPROXY entry jump enabled' >&2
    exit 1
fi
apply /tmp/tproxy.json
assert_active tproxy
assert_tproxy_rule
echo 'OpenWrt: saved TPROXY and TPROXY → REDIRECT → TPROXY passed'

kill "$pid"
wait "$pid"
pid=
sh /work/update-guard.sh
