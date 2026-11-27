"""Exercise the opt-in firmware autoload guard on managed Entware updates."""
from pathlib import Path

from test_bootstrap import BootstrapFixture


class AutoloadGuardTest(BootstrapFixture):
    def setUp(self) -> None:
        super().setUp()
        self.blocked = {4: self.prefix / 'forwarding-blocked-4',
                        6: self.prefix / 'forwarding-blocked-6'}
        self.running = self.prefix / 'running'
        self.events = self.prefix / 'events'
        firewall = '''
case "${0##*/}" in iptables) family=4 ;; ip6tables) family=6 ;; esac
blocked="$KEENPROXY_PREFIX/forwarding-blocked-$family"
case "$*" in
    *'-t nat -S') exit 0 ;;
    *'-t nat -C PREROUTING -j KEENPROXY_DNS'|*'-t nat -C PREROUTING -j KEENPROXY_TCP')
        test -f "$KEENPROXY_PREFIX/running" ;;
    *'-t mangle -S') exit 0 ;;
    *'-C FORWARD '*'-j DROP')
        echo discover >> "$KEENPROXY_PREFIX/events"
        test -f "$blocked" ;;
    *'-I FORWARD '*'-j DROP')
        echo insert >> "$KEENPROXY_PREFIX/events"
        [ ! -f "$KEENPROXY_PREFIX/firewall-failure-$family" ] || exit 1
        touch "$blocked" ;;
    *'-D FORWARD '*'-j DROP')
        echo release >> "$KEENPROXY_PREFIX/events"
        rm -f "$blocked" ;;
    *) exit 2 ;;
esac
'''
        for name in ('iptables', 'ip6tables'):
            self.executable(self.prefix / 'sbin' / name, firewall)
        self.old_asset = self.release('v1.2.3')
        self.add_autoload(self.old_asset, 'old')
        self.assert_panel_access(self.install())
        self.old = self.binary.read_bytes()

    @property
    def marker(self) -> Path:
        return self.config.with_name('config.yaml.autoload-guard')

    def add_autoload(self, asset: Path, label: str, status: int = 0,
                     unsupported: bool = False) -> None:
        script = asset.read_text()
        shebang = '#!/bin/sh\n'
        self.assertTrue(script.startswith(shebang))
        handler = (
            'if [ "$1" = -autoload-update-guard ]; then\n'
            f"    printf '%s|%s|%s\\n' '{label}' \"$0\" \"$*\" >> \"$KEENPROXY_PREFIX/events\"\n"
            + ('    echo "flag provided but not defined: -autoload-update-guard" >&2\n'
               if unsupported else '')
            + f'    exit {status}\n'
            'fi\n'
        )
        asset.write_text(shebang + handler + script[len(shebang):])
        self.write_checksums(asset.parent)

    def event_lines(self):
        if not self.events.exists():
            return []
        return self.events.read_text().splitlines()

    def test_saved_guard_runs_verified_candidate_before_guard_rules(self) -> None:
        self.marker.touch()
        candidate = self.release('v1.2.4')
        self.add_autoload(candidate, 'candidate')

        result = self.install('--version', 'v1.2.4')

        self.assert_panel_access(result)
        self.assertNotIn('could not restore', result.stderr)
        self.assertEqual(self.binary.read_bytes(), candidate.read_bytes())
        lines = self.event_lines()
        invocations = [line for line in lines if line.startswith('candidate|')]
        self.assertEqual(len(invocations), 1, lines)
        _, path, arguments = invocations[0].split('|', 2)
        self.assertEqual(
            arguments,
            f'-autoload-update-guard -config {self.config} '
            f'-iptables {self.prefix}/sbin/iptables')
        self.assertTrue(path.endswith('/payload/bin/keenproxy'), path)
        self.assertTrue(
            path.startswith(f'{self.prefix}/tmp/keenproxy-release.'), path)
        self.assertNotEqual(path, str(self.binary))
        self.assertFalse(any(line.startswith('old|') for line in lines), lines)
        first_rule = min(index for index, line in enumerate(lines)
                         if line in ('discover', 'insert'))
        self.assertLess(lines.index(invocations[0]), first_rule)
        self.assertIn('insert', lines)
        self.assertTrue(self.marker.exists())
        self.assertFalse(any(rule.exists() for rule in self.blocked.values()))

    def test_update_without_marker_does_not_run_autoload_guard(self) -> None:
        candidate = self.release('v1.2.4')
        self.add_autoload(candidate, 'candidate')

        result = self.install('--version', 'v1.2.4')

        self.assert_panel_access(result)
        self.assertEqual(self.binary.read_bytes(), candidate.read_bytes())
        self.assertFalse(any(line.startswith('candidate|')
                             for line in self.event_lines()))
        self.assertIn('insert', self.event_lines())
        self.assertNotIn('autoload', result.stderr)

    def test_same_version_noop_does_not_run_autoload_guard(self) -> None:
        self.marker.touch()

        result = self.install('--version', 'v1.2.3')

        self.assert_panel_access(result)
        lines = self.event_lines()
        self.assertFalse(any(line.startswith('old|') for line in lines))
        self.assertNotIn('insert', lines)
        self.assertNotIn('release', lines)
        self.assertNotIn('autoload', result.stderr)

    def test_legacy_downgrade_uses_managed_snapshot_before_guard_rules(self) -> None:
        self.marker.touch()
        candidate = self.release('v1.2.2')
        self.add_autoload(candidate, 'candidate', status=2, unsupported=True)

        result = self.install('--version', 'v1.2.2', '--require-guard')

        self.assert_panel_access(result)
        self.assertNotIn('could not restore', result.stderr)
        self.assertEqual(self.binary.read_bytes(), candidate.read_bytes())
        lines = self.event_lines()
        rejected = next(i for i, line in enumerate(lines) if line.startswith('candidate|'))
        fallback = next(i for i, line in enumerate(lines) if line.startswith('old|'))
        self.assertLess(rejected, fallback)
        self.assertLess(fallback, lines.index('discover'))
        self.assertIn('/previous/bin/keenproxy|', lines[fallback])

    def test_rejected_option_warns_and_keeps_best_effort_guard_policy(self) -> None:
        self.marker.touch()
        candidate = self.release('v1.2.4')
        self.add_autoload(candidate, 'candidate', status=2)
        (self.prefix / 'firewall-failure-4').touch()

        result = self.install('--version', 'v1.2.4')

        self.assert_panel_access(result)
        self.assertIn('could not restore the saved firmware module autoload guard',
                      result.stderr)
        self.assertIn('could not block IPv4 forwarding', result.stderr)
        self.assertEqual(self.binary.read_bytes(), candidate.read_bytes())
        self.assertTrue(self.running.exists())
        self.assertFalse(any(rule.exists() for rule in self.blocked.values()))

    def test_rejected_option_preserves_require_guard_success(self) -> None:
        self.marker.touch()
        candidate = self.release('v1.2.4')
        self.add_autoload(candidate, 'candidate', status=2)

        result = self.install('--version', 'v1.2.4', '--require-guard')

        self.assert_panel_access(result)
        self.assertIn('could not restore the saved firmware module autoload guard',
                      result.stderr)
        self.assertNotIn('could not block IPv4 forwarding', result.stderr)
        self.assertIn('insert', self.event_lines())
        self.assertEqual(self.binary.read_bytes(), candidate.read_bytes())
        self.assertFalse(any(rule.exists() for rule in self.blocked.values()))

    def test_rejected_option_keeps_require_guard_policy(self) -> None:
        self.marker.touch()
        candidate = self.release('v1.2.4')
        self.add_autoload(candidate, 'candidate', status=2)
        (self.prefix / 'firewall-failure-4').touch()

        result = self.install('--version', 'v1.2.4', '--require-guard')

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('could not restore the saved firmware module autoload guard',
                      result.stderr)
        self.assertIn('could not block IPv4 forwarding; service left unchanged',
                      result.stderr)
        self.assertEqual(self.binary.read_bytes(), self.old)
        self.assertTrue(self.running.exists())
        self.assertFalse(any(rule.exists() for rule in self.blocked.values()))
