"""Exercise the bootstrap transaction with a stateful forwarding boundary."""
from pathlib import Path

from test_bootstrap import BootstrapFixture


class UpdateGuardTest(BootstrapFixture):
    def setUp(self) -> None:
        super().setUp()
        self.blocked = {4: self.prefix / 'forwarding-blocked-4',
                        6: self.prefix / 'forwarding-blocked-6'}
        self.running = self.prefix / 'running'
        firewall = '''
case "${0##*/}" in iptables) family=4 ;; ip6tables) family=6 ;; esac
blocked="$KEENPROXY_PREFIX/forwarding-blocked-$family"
running="$KEENPROXY_PREFIX/running"
case "$*" in
    *'-t nat -S') exit 0 ;;
    *'-t nat -C PREROUTING -j KEENPROXY_DNS'|*'-t nat -C PREROUTING -j KEENPROXY_TCP')
        [ -f "$running" ] && ! grep -Fxq '# parked' "$KEENPROXY_PREFIX/bin/keenproxy" ;;
    *'-t mangle -S')
        if grep -Fxq '# unreadable mangle' "$KEENPROXY_PREFIX/bin/keenproxy"; then exit 4; fi
        if [ -f "$KEENPROXY_PREFIX/tproxy" ]; then
            echo '-N KEENPROXY_UDP'
            if [ -f "$KEENPROXY_PREFIX/udp-ready" ]; then echo '-A PREROUTING -j KEENPROXY_UDP'; fi
        fi ;;
    *'-C FORWARD '*'-j DROP') test -f "$blocked" ;;
    *'-I FORWARD '*'-j DROP')
        [ "$family" = 6 ] || [ ! -f "$KEENPROXY_PREFIX/firewall-failure" ] || exit 1
        touch "$blocked" ;;
    *'-D FORWARD '*'-j DROP')
        # A failed preflight can remove the IPv6 guard while the old service runs.
        if [ ! -f "$running" ] ||
            { [ -f "$KEENPROXY_PREFIX/tproxy" ] && [ ! -f "$KEENPROXY_PREFIX/udp-ready" ]; }; then
            touch "$KEENPROXY_PREFIX/forwarding-exposed"
        fi
        rm -f "$blocked" ;;
    *) exit 2 ;;
esac
'''
        for name in ('iptables', 'ip6tables'):
            self.executable(self.prefix / 'sbin' / name, firewall)
        self.command('sleep', 'touch "$KEENPROXY_PREFIX/udp-ready"')
        old = self.release('v1.2.3', stop='''
        [ -f "$KEENPROXY_PREFIX/forwarding-blocked-4" ] ||
            touch "$KEENPROXY_PREFIX/forwarding-exposed"
        rm -f "$state"
        ''')
        self.record_starts(old)
        self.old = old.read_bytes()
        self.assert_panel_access(self.install())

    def record_starts(self, asset: Path) -> None:
        tag = asset.parent.name
        script = asset.read_text().replace(
            'if [ "$1" = --fixture-start ]; then exit ',
            f'if [ "$1" = --fixture-start ]; then echo {tag} >> "$KEENPROXY_PREFIX/starts"; exit ',
        )
        asset.write_text(script)
        self.write_checksums(asset.parent)

    def assert_released(self) -> None:
        self.assertFalse(any(rule.exists() for rule in self.blocked.values()))
        self.assertFalse((self.prefix / 'forwarding-exposed').exists())

    def test_update_blocks_forwarding_until_candidate_starts(self) -> None:
        candidate = self.release('v1.2.4')

        self.assert_panel_access(self.install('--version', 'v1.2.4'))

        self.assertEqual(self.binary.read_bytes(), candidate.read_bytes())
        self.assert_released()

    def test_failed_update_blocks_forwarding_until_rollback_starts(self) -> None:
        self.record_starts(self.release('v1.2.4', start=False))

        result = self.install('--version', 'v1.2.4')

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.binary.read_bytes(), self.old)
        self.assertTrue(self.running.exists())
        self.assertEqual((self.prefix / 'starts').read_text().splitlines(),
                         ['v1.2.3', 'v1.2.4', 'v1.2.3'])
        self.assert_released()

    def test_guard_waits_for_legacy_tproxy_jump_after_dns_jump(self) -> None:
        self.release('v1.2.4')
        (self.prefix / 'tproxy').touch()

        self.assert_panel_access(self.install('--version', 'v1.2.4'))

        self.assertTrue((self.prefix / 'udp-ready').exists())
        self.assert_released()

    def test_management_only_candidate_does_not_release_forwarding(self) -> None:
        candidate = self.release('v1.2.4')
        candidate.write_bytes(candidate.read_bytes() + b'\n# parked\n')
        self.record_starts(candidate)

        result = self.install('--version', 'v1.2.4')

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.binary.read_bytes(), self.old)
        self.assertEqual((self.prefix / 'starts').read_text().splitlines(),
                         ['v1.2.3', 'v1.2.4', 'v1.2.3'])
        self.assert_released()

    def test_guard_rolls_back_when_mangle_inspection_fails(self) -> None:
        candidate = self.release('v1.2.4')
        candidate.write_bytes(candidate.read_bytes() + b'\n# unreadable mangle\n')
        self.record_starts(candidate)

        result = self.install('--version', 'v1.2.4')

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.binary.read_bytes(), self.old)
        self.assertEqual((self.prefix / 'starts').read_text().splitlines(),
                         ['v1.2.3', 'v1.2.4', 'v1.2.3'])
        self.assert_released()

    def test_update_does_not_stop_running_service_if_blocking_fails(self) -> None:
        self.release('v1.2.4')
        (self.prefix / 'firewall-failure').touch()

        result = self.install('--version', 'v1.2.4')

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.binary.read_bytes(), self.old)
        self.assertTrue(self.running.exists())
        self.assertFalse((self.prefix / 'forwarding-exposed').exists())

    def test_failed_rollback_keeps_forwarding_blocked_until_retry(self) -> None:
        self.record_starts(self.release('v1.2.4', start=False))
        self.binary.write_bytes(self.old.replace(b'/starts"; exit 0', b'/starts"; exit 1'))

        result = self.install('--version', 'v1.2.4')

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.running.exists())
        self.assertTrue(self.blocked[4].exists())
        self.assertEqual((self.prefix / 'starts').read_text().splitlines(),
                         ['v1.2.3', 'v1.2.4', 'v1.2.3'])
        self.assertFalse((self.prefix / 'forwarding-exposed').exists())
        self.assert_panel_access(self.install('--version', 'v1.2.3'))
        self.assert_released()
