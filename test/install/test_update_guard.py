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
        [ ! -f "$KEENPROXY_PREFIX/firewall-failure-$family" ] || exit 1
        touch "$blocked" ;;
    *'-D FORWARD '*'-j DROP')
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
        self.old_asset = self.release('v1.2.3', stop='''
        [ -f "$KEENPROXY_PREFIX/forwarding-blocked-4" ] ||
            touch "$KEENPROXY_PREFIX/forwarding-exposed"
        rm -f "$state"
        ''')
        self.record_starts(self.old_asset)
        self.old = self.old_asset.read_bytes()
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

    def test_update_continues_when_no_guard_can_be_installed(self) -> None:
        candidate = self.release('v1.2.4')
        self.reject_guards()

        result = self.install('--version', 'v1.2.4')

        self.assert_panel_access(result)
        self.assertIn('could not block IPv4 forwarding', result.stderr)
        self.assertEqual(self.binary.read_bytes(), candidate.read_bytes())
        self.assertTrue(self.running.exists())
        self.assertTrue((self.prefix / 'forwarding-exposed').exists())
        self.assertFalse(any(rule.exists() for rule in self.blocked.values()))

    def test_ipv6_guard_failure_preserves_ipv4_protection(self) -> None:
        self.require_ipv6_forwarding()
        candidate = self.release('v1.2.4')
        (self.prefix / 'firewall-failure-6').touch()

        result = self.install('--version', 'v1.2.4')

        self.assert_panel_access(result)
        self.assertIn('could not block IPv6 forwarding', result.stderr)
        self.assertNotIn('could not block IPv4 forwarding', result.stderr)
        self.assertEqual(self.binary.read_bytes(), candidate.read_bytes())
        self.assert_released()

    def test_missing_ip6tables_warns_that_previous_guard_cannot_be_checked(self) -> None:
        self.require_ipv6_forwarding()
        candidate = self.release('v1.2.4')
        self.blocked[6].touch()
        (self.prefix / 'sbin/ip6tables').unlink()

        result = self.install('--version', 'v1.2.4')

        self.assert_panel_access(result)
        self.assertIn('cannot check or block IPv6 forwarding', result.stderr)
        self.assertIn('restore ip6tables and rerun the bootstrap', result.stderr)
        self.assertEqual(self.binary.read_bytes(), candidate.read_bytes())
        self.assertFalse(self.blocked[4].exists())
        self.assertTrue(self.blocked[6].exists())

    def require_ipv6_forwarding(self) -> None:
        if not any(control.read_text().strip() == '1'
                   for control in Path('/proc/sys/net/ipv6/conf').glob('*/forwarding')):
            self.skipTest('requires IPv6 forwarding (run in a disposable Linux namespace)')

    def test_retry_does_not_accept_unhealthy_rollback_without_guard(self) -> None:
        self.release('v1.2.4', start=False)
        self.reject_guards()
        parked = self.old + b'\n# parked\n'
        self.old_asset.write_bytes(parked)
        self.write_checksums(self.old_asset.parent)
        self.binary.write_bytes(parked)

        failed = self.install('--version', 'v1.2.4')
        retry = self.install('--version', 'v1.2.3')

        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('previous service did not restore routing', failed.stderr)
        self.assertNotEqual(retry.returncode, 0)
        self.assertIn('running service does not have active routing', retry.stderr)
        self.assertNotIn('Access URL:', retry.stdout)
        self.assertTrue(self.running.exists())
        self.assertEqual((self.prefix / 'starts').read_text().splitlines(),
                         ['v1.2.3', 'v1.2.3'])

    def test_same_version_retry_accepts_routing_restored_after_startup(self) -> None:
        state = self.prefix / 'var/run/keenproxy/startup-state'
        state.write_text('management-only 1234\n')

        self.assert_panel_access(self.install('--version', 'v1.2.3'))

        self.assertEqual((self.prefix / 'starts').read_text().splitlines(), ['v1.2.3'])

    def test_update_still_rolls_back_without_guard_if_routing_fails(self) -> None:
        candidate = self.release('v1.2.4')
        candidate.write_bytes(candidate.read_bytes() + b'\n# parked\n')
        self.record_starts(candidate)
        self.reject_guards()

        result = self.install('--version', 'v1.2.4')

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('traffic interception is not active', result.stderr)
        self.assertEqual(self.binary.read_bytes(), self.old)
        self.assertTrue(self.running.exists())
        self.assertEqual((self.prefix / 'starts').read_text().splitlines(),
                         ['v1.2.3', 'v1.2.4', 'v1.2.3'])

    def reject_guards(self) -> None:
        for family in self.blocked:
            (self.prefix / f'firewall-failure-{family}').touch()

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
