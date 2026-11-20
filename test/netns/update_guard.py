"""Send real packets across the disposable router during a release replacement."""
from pathlib import Path
import subprocess
import unittest

from test_bootstrap import BootstrapFixture


class UpdateGuardPackets(BootstrapFixture):
    def publish(self, tag: str, *, start: bool = True) -> None:
        asset = self.release(tag, start=start)
        self.executable(asset.with_name('S99keenproxy'), '''# KeenProxy Entware service
set -eu
state="$KEENPROXY_PREFIX/running"
case "$1" in
    check) test -f "$state" ;;
    start)
        if [ -f "$KEENPROXY_PREFIX/check-window" ]; then forwarding-is-blocked; fi
        "$KEENPROXY_PREFIX/bin/keenproxy" --fixture-start
        iptables -t nat -A PREROUTING -j KEENPROXY_DNS
        iptables -t nat -A PREROUTING -j KEENPROXY_TCP
        touch "$state" ;;
    stop)
        if [ -f "$state" ]; then
            iptables -t nat -D PREROUTING -j KEENPROXY_DNS
            iptables -t nat -D PREROUTING -j KEENPROXY_TCP
            rm -f "$state"
        fi
        forwarding-is-blocked ;;
    *) exit 2 ;;
esac
''')
        self.write_checksums(asset.parent)

    def setUp(self) -> None:
        super().setUp()
        # GitHub runners lack the legacy IPv6 filter table. Exercise legacy
        # IPv4 interception alongside the nft-backed IPv6 forwarding guard.
        for tool, backend in (('iptables', 'iptables-legacy'),
                              ('iptables-restore', 'iptables-legacy-restore'),
                              ('ip6tables', 'ip6tables-nft')):
            target = self.prefix / 'sbin' / tool
            target.unlink(missing_ok=True)
            target.symlink_to(Path('/usr/sbin') / backend)
        self.command('forwarding-is-blocked', '''
set -eu
probe() { ip netns exec client ping -n -c 1 -W 1 "$1" >/dev/null; }
if probe 198.51.100.3 || probe 2001:db8:2::2; then
    touch "$KEENPROXY_PREFIX/leak"
    exit 1
fi
probe 192.168.77.1
probe 2001:db8:1::1
''')
        for chain in ('KEENPROXY_DNS', 'KEENPROXY_TCP'):
            subprocess.run(['iptables-legacy', '-t', 'nat', '-N', chain],
                           check=True)
        self.publish('v1.2.3')
        self.assert_panel_access(self.install())
        (self.prefix / 'check-window').touch()

    def assert_forwarding(self) -> None:
        for address in ('198.51.100.3', '2001:db8:2::2'):
            probe = subprocess.run(
                ['ip', 'netns', 'exec', 'client', 'ping', '-n', '-c', '1', '-W', '1',
                 address], capture_output=True, text=True, timeout=5)
            self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)

    def test_guard_drops_forwarded_packets_but_leaves_router_reachable(self) -> None:
        self.assert_forwarding()
        self.publish('v1.2.4', start=False)
        self.publish('v1.2.5')

        failed = self.install('--version', 'v1.2.4')
        self.assertNotEqual(failed.returncode, 0, failed.stdout)
        self.assertIn('new service failed to start with routing', failed.stderr)
        self.assertIn('restoring the previous installation', failed.stderr)
        self.assertFalse((self.prefix / 'leak').exists(), failed.stderr)
        self.assertTrue((self.prefix / 'running').exists(), failed.stderr)
        self.assert_forwarding()

        self.assert_panel_access(self.install('--version', 'v1.2.5'))
        self.assertFalse((self.prefix / 'leak').exists())
        self.assert_forwarding()


if __name__ == '__main__':
    unittest.main(verbosity=2)
