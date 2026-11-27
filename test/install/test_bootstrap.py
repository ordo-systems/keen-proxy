"""Exercise release installation without network or a live router."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ACCESS_URL = 'http://192.0.2.10:8086'

class BootstrapFixture(unittest.TestCase):
    prefix_name = 'opt'
    bootstrap_script = ROOT / 'tools/bootstrap.sh'

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.prefix = self.root / self.prefix_name
        self.commands = self.root / 'commands'
        self.commands.mkdir()
        self.mirror = self.root / 'mirror'
        self.mirror.mkdir()
        self.requests = self.root / 'requests'
        self.env = dict(os.environ, PATH=f'{self.commands}:{os.environ["PATH"]}',
                        KEENPROXY_PREFIX=str(self.prefix), FIXTURES=str(self.mirror),
                        REQUESTS=str(self.requests), CPU='aarch64')
        self.command('uname', 'echo "$CPU"')
        self.command('hexdump', 'printf "%s" "${ELF_HEADER:-7f454c460201}"')
        self.command('head', '''
case "$*" in
    *'/proc/self/exe'*) printf fixture ;;
    *) exec /usr/bin/head "$@" ;;
esac''')
        self.command('pidof', 'exit 1')
        self.command('curl', '''
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) out=$2; shift ;;
        https://*) url=$1 ;;
    esac
    shift
done
printf '%s\\n' "$url" >> "$REQUESTS"
case "$url" in
    */releases/latest) cat "$FIXTURES/latest"; exit ;;
    */main/version.txt) path=version.txt ;;
    */releases/download/*) path=${url#*/releases/download/} ;;
    *) exit 22 ;;
esac
cp "$FIXTURES/$path" "$out"
''')
        for path in ('bin', 'sbin', 'etc/init.d'):
            (self.prefix / path).mkdir(parents=True)
        for name in ('iptables', 'iptables-restore', 'ip6tables'):
            self.executable(self.prefix / 'sbin' / name, 'exit 0')
        self.executable(self.prefix / 'etc/init.d/rc.unslung', 'exit 0')
        (self.mirror / 'version.txt').write_text('1.2.3\n')
        self.latest_release('v1.2.3')

    def latest_release(self, tag):
        (self.mirror / 'latest').write_text(
            f'https://github.com/ordo-systems/keen-proxy/releases/tag/{tag}')

    def executable(self, path, script):
        path.write_text('#!/bin/sh\n' + script + '\n')
        path.chmod(0o755)

    def command(self, name, script):
        self.executable(self.commands / name, script)

    def url_boundary(self, trailer):
        return (
            'if [ "$#" -ne 3 ] || [ "$2" != -config ] || [ ! -f "$3" ]; then\n'
            '    echo rejected-url-args >&2\n'
            '    exit 2\n'
            'fi\n'
            'echo "queried -config $3" >> "$KEENPROXY_PREFIX/url-invocations"\n'
            + trailer
        )

    def release(self, tag, arch='arm64', lite=False, start=True, dry_run='exit 0',
                stop='rm -f "$state"', url=None):
        if url is None:
            url = self.url_boundary(f"echo '{ACCESS_URL}'\nexit 0\n")
        folder = self.mirror / tag
        folder.mkdir()
        asset = f'keenproxy-{"lite-" if lite else ""}linux-{arch}'
        script = (
            '#!/bin/sh\n'
            f'# {tag}\n'
            'if [ "$1" = --key ]; then echo leaked-panel-token; exit 0; fi\n'
            f'if [ "$1" = --fixture-start ]; then exit {0 if start else 1}; fi\n'
            'if [ "$1" = --url ]; then\n'
            + url +
            'fi\n'
            + dry_run + '\n'
        )
        (folder / asset).write_text(script)
        (folder / 'install.sh').write_bytes((ROOT / 'tools/install.sh').read_bytes())
        self.executable(folder / 'S99keenproxy', f'''# KeenProxy Entware service
state="$KEENPROXY_PREFIX/running"
test -n "${{KEENPROXY_SERVICE_LOCK_TOKEN:-}}" || exit 1
case "$1" in
    start) "$KEENPROXY_PREFIX/bin/keenproxy" --fixture-start && touch "$state" ;;
    check) test -f "$state" ;;
    stop) {stop} ;;
    *) exit 2 ;;
esac''')
        self.write_checksums(folder)
        return folder / asset

    def write_checksums(self, folder):
        (folder / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
            for p in sorted(folder.iterdir()) if p.name != 'SHA256SUMS'))

    def install(self, *args):
        return self.bootstrap(*args)

    def bootstrap(self, *args, shell='sh'):
        with self.bootstrap_script.open('rb') as script:
            return subprocess.run([shell, '-s', '--', *args],
                                  stdin=script, env=self.env, capture_output=True,
                                  text=True, timeout=20)

    @property
    def binary(self):
        return self.prefix / 'bin/keenproxy'

    @property
    def config(self):
        return self.prefix / 'etc/keenproxy/config.yaml'

    @property
    def service(self):
        return self.prefix / 'etc/init.d/S99keenproxy'

    def token_command(self):
        return f"'{self.binary}' --key -config '{self.config}'"

    def assert_panel_access(self, result, url=ACCESS_URL):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            f'Access URL: {url}\n'
            f'Retrieve existing panel token: {self.token_command()}\n',
            result.stdout)
        self.assertNotIn('0.0.0.0', result.stdout)
        self.assertNotIn('leaked-panel-token', result.stdout + result.stderr)
        self.assertNotIn('rejected-url-args', result.stdout + result.stderr)

    def assert_url_queries(self, count):
        recorded = (self.prefix / 'url-invocations').read_text().splitlines()
        self.assertEqual(recorded, [f'queried -config {self.config}'] * count)


class BootstrapTest(BootstrapFixture):
    @property
    def release_record(self):
        return self.prefix / 'share/keenproxy/release'

    def assert_release(self, current, previous='', variant='full'):
        self.assertEqual(self.release_record.read_text(),
                         f'current {current}\nprevious {previous}\nvariant {variant}\n')
        self.assertEqual(self.release_record.stat().st_mode & 0o777, 0o600)

    def test_release_bootstrap_recovers_staging_failure_once(self):
        self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        asset = self.release('v0.10.2', lite=True)
        folder = asset.parent
        (folder / 'install.sh').write_text('exit 17\n')
        (folder / 'bootstrap.sh').write_text('''
set -eu
test "$*" = '--version v0.10.2 --expect-current v1.2.3 --lite --require-guard --without-trusttunnel'
test -f "$KEENPROXY_PREFIX/running"
test ! -e "$KEENPROXY_PREFIX/var/lock/keenproxy-install.lock"
printf '%s\\n' "$*" >> "$KEENPROXY_PREFIX/fallback"
''')
        self.write_checksums(folder)
        result = self.bootstrap('--version', 'v0.10.2', '--expect-current', 'v1.2.3',
                                '--lite', '--require-guard', '--without-trusttunnel', shell='bash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len((self.prefix / 'fallback').read_text().splitlines()), 1)
        self.assert_release('v1.2.3')

    def test_unsupported_architecture_delegates_to_release_bootstrap(self):
        folder = self.release('v0.10.2').parent
        (folder / 'bootstrap.sh').write_text('test "$*" = "--version v0.10.2"\n')
        self.write_checksums(folder)
        self.env['CPU'] = 'unsupported'
        # An inherited asset name must not act as a cleanup path.
        self.env['asset'] = 'bootstrap.sh'
        result = self.install('--version', 'v0.10.2')
        self.assertEqual(result.returncode, 0, result.stderr)
        requests = self.requests.read_text().splitlines()
        self.assertEqual(len(requests), 2)
        self.assertTrue(requests[-1].endswith('/v0.10.2/bootstrap.sh'))

    def test_checked_release_bootstrap_completes_install(self):
        folder = self.release(
            'v0.10.2', dry_run='''
if [ -f "$KEENPROXY_PREFIX/preflight-attempted" ]; then
    test -z "${KEENPROXY_BOOTSTRAP_RETRY+x}" &&
        test "$(find "$KEENPROXY_PREFIX/tmp" -name keenproxy-linux-arm64 | wc -l)" -eq 1
    exit $?
fi
touch "$KEENPROXY_PREFIX/preflight-attempted"
exit 1
''').parent
        (folder / 'bootstrap.sh').write_bytes(self.bootstrap_script.read_bytes())
        self.write_checksums(folder)
        result = self.install('--version', 'v0.10.2')
        self.assert_panel_access(result)
        self.assert_release('v0.10.2')
        self.assertTrue((self.prefix / 'running').exists())
        self.assertFalse((self.prefix / 'var/lock/keenproxy-install.lock').exists())

    def test_bad_fallback_checksum_is_not_executed(self):
        folder = self.release('v0.10.2', dry_run='exit 1').parent
        script = folder / 'bootstrap.sh'
        script.write_text('exit 0\n')
        self.write_checksums(folder)
        script.write_text('touch "$KEENPROXY_PREFIX/unverified-script-ran"\n')
        result = self.install('--version', 'v0.10.2')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA256 mismatch for bootstrap.sh', result.stderr)
        self.assertFalse((self.prefix / 'unverified-script-ran').exists())
        self.assertFalse(self.binary.exists())

    def test_fallback_failure_does_not_loop_or_mask_error(self):
        folder = self.release('v0.10.2', dry_run='exit 1').parent
        (folder / 'bootstrap.sh').write_bytes(self.bootstrap_script.read_bytes())
        self.write_checksums(folder)
        self.latest_release('v0.10.2')
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        requests = self.requests.read_text().splitlines()
        self.assertEqual(sum(url.endswith('/v0.10.2/bootstrap.sh') for url in requests), 1)
        self.assertEqual(sum(url.endswith('/releases/latest') for url in requests), 1)
        self.assertFalse((self.prefix / 'var/lock/keenproxy-install.lock').exists())
        self.assertEqual(list((self.prefix / 'tmp').glob('keenproxy-release.*')), [])
        self.assertFalse(self.binary.exists())

    def test_uninstall_stops_service_and_preserves_settings_without_network(self):
        self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        token = self.config.with_name('token')
        token.write_text('test token\n')
        self.config.write_text('schema_version: 1\n# local settings\n')
        client = self.prefix / 'bin/trusttunnel_client'
        self.executable(client, 'exit 0')
        before = self.requests.read_bytes()
        self.env['CPU'] = 'unsupported'
        for _ in range(2):
            result = self.bootstrap('--uninstall')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((self.prefix / 'running').exists())
            self.assertFalse(self.binary.exists())
            self.assertFalse(self.service.exists())
            self.assertFalse(self.release_record.exists())
            self.assertEqual(token.read_text(), 'test token\n')
            self.assertNotIn('test token', result.stdout + result.stderr)
            self.assertNotIn('Access URL:', result.stdout)
            self.assertIn('# local settings', self.config.read_text())
            self.assertTrue(client.exists())
        self.assertEqual(self.requests.read_bytes(), before)

    def test_uninstall_removes_owned_netfilter_hook_left_by_dead_process(self):
        self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        hook = self.netfilter_hook()
        (self.prefix / 'running').unlink()

        result = self.bootstrap('--uninstall')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(hook.exists())

    def test_uninstall_removes_owned_hook_after_an_earlier_uninstall(self):
        hook = self.netfilter_hook()

        result = self.bootstrap('--uninstall')

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(hook.exists())

    def test_uninstall_keeps_foreign_netfilter_hooks(self):
        hook = self.netfilter_hook()
        foreign = '#!/bin/sh\n# operator netfilter hook\n'
        hook.write_text(foreign)
        self.assertEqual(self.bootstrap('--uninstall').returncode, 0)
        self.assertEqual(hook.read_text(), foreign)

        hook.unlink()
        target = self.root / 'operator-hook'
        target.write_text('#!/bin/sh\n# keenproxy-netfilter-hook-v1\n')
        hook.symlink_to(target)
        self.assertEqual(self.bootstrap('--uninstall').returncode, 0)
        self.assertTrue(hook.is_symlink())
        self.assertTrue(target.exists())

    def test_uninstall_keeps_owned_hook_while_unmanaged_process_runs(self):
        hook = self.netfilter_hook()
        self.command('pidof', 'exit 0')

        result = self.bootstrap('--uninstall')

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unmanaged process', result.stderr)
        self.assertTrue(hook.exists())

    def netfilter_hook(self):
        hook = self.prefix / 'etc/ndm/netfilter.d/99-keenproxy.sh'
        hook.parent.mkdir(parents=True)
        self.executable(hook, '# keenproxy-netfilter-hook-v1\nexit 0')
        return hook

    def test_uninstall_refuses_an_unmanaged_binary(self):
        self.executable(self.binary, 'echo old')
        result = self.bootstrap('--uninstall')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unmanaged', result.stderr)
        self.assertIn('echo old', self.binary.read_text())
        self.assertFalse(self.requests.exists())

    def test_uninstall_preserves_installation_when_stop_fails(self):
        binary = self.release('v1.2.3', stop='exit 1')
        self.assertEqual(self.install().returncode, 0)
        hook = self.netfilter_hook()
        result = self.bootstrap('--uninstall')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('did not stop', result.stderr)
        self.assertTrue(hook.exists())
        self.assertEqual(self.binary.read_bytes(), binary.read_bytes())
        self.assertTrue(self.service.exists())
        self.assertTrue((self.prefix / 'running').exists())

    def test_uninstall_rolls_back_a_partial_removal(self):
        binary = self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        service = self.service.read_bytes()
        self.command('rm', """
for path in "$@"; do
    [ "$path" != "$KEENPROXY_PREFIX/etc/init.d/S99keenproxy" ] || exit 1
done
exec /bin/rm "$@"
""")
        result = self.bootstrap('--uninstall')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('restoring the previous installation', result.stderr)
        self.assertEqual(self.binary.read_bytes(), binary.read_bytes())
        self.assertEqual(self.service.read_bytes(), service)
        self.assert_release('v1.2.3')
        self.assertTrue((self.prefix / 'running').exists())

    def test_uninstall_restores_hook_on_failed_removal(self):
        self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        hook = self.netfilter_hook()
        before = hook.read_bytes()
        self.command('rm', """
/bin/rm "$@" || exit
for path in "$@"; do
    [ "$path" != "$KEENPROXY_PREFIX/etc/ndm/netfilter.d/99-keenproxy.sh" ] || exit 1
done
""")

        result = self.bootstrap('--uninstall')

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('restoring the previous installation', result.stderr)
        self.assertTrue(self.service.exists())
        self.assertEqual(hook.read_bytes(), before)
        self.assertTrue((self.prefix / 'running').exists())

    def test_bootstrap_installs_starts_and_preserves_configuration_on_update(self):
        first = self.release('v1.2.3')
        result = self.install()
        self.assert_panel_access(result)
        self.assertEqual(self.binary.read_bytes(), first.read_bytes())
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assert_release('v1.2.3')
        self.assertTrue((self.prefix / 'running').exists())
        self.assert_url_queries(1)
        self.config.write_text('schema_version: 1\n# user setting\n')
        token = self.config.with_name('token')
        token.write_text('test fixture\n')
        next_release = self.release('v1.2.4')
        self.latest_release('v1.2.4')
        for _ in range(2):
            result = self.install()
            self.assert_panel_access(result)
            self.assertNotIn('test fixture', result.stdout + result.stderr)
            self.assert_release('v1.2.4', 'v1.2.3')
        self.assertEqual(self.binary.read_bytes(), next_release.read_bytes())
        self.assertIn('# user setting', self.config.read_text())
        self.assertEqual(token.read_text(), 'test fixture\n')
        self.assert_url_queries(3)

    def test_url_query_problems_keep_installation_and_hide_command_output(self):
        self.release('v1.2.3', url=self.url_boundary('echo synthetic-secret >&2\nexit 1\n'))
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('could not determine the panel access URL', result.stderr)
        self.assertNotIn('Access URL:', result.stdout)
        self.assertNotIn('synthetic-secret', result.stdout + result.stderr)
        self.assertNotIn('leaked-panel-token', result.stdout + result.stderr)
        self.assertIn(f'Retrieve existing panel token: {self.token_command()}\n', result.stdout)
        self.assertTrue((self.prefix / 'running').exists())
        self.assert_release('v1.2.3')
        self.assert_url_queries(1)
        self.release('v1.2.4', url=self.url_boundary('exit 0\n'))
        self.latest_release('v1.2.4')
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('could not determine the panel access URL', result.stderr)
        self.assertNotIn('Access URL:', result.stdout)
        self.assertNotIn('synthetic-secret', result.stdout + result.stderr)
        self.assertIn(f'Retrieve existing panel token: {self.token_command()}\n', result.stdout)
        self.assert_release('v1.2.4', 'v1.2.3')
        self.assertTrue((self.prefix / 'running').exists())
        self.assertEqual(self.binary.read_bytes(), (self.mirror / 'v1.2.4/keenproxy-linux-arm64').read_bytes())
        self.assert_url_queries(2)

    def test_existing_updater_can_install_a_native_release(self):
        release = self.release('v1.2.3')
        for script in (ROOT / 'tools/bootstrap.sh',
                       ROOT / 'test/install/fixtures/bootstrap-external-client.sh'):
            with self.subTest(script=script.name):
                self.bootstrap_script = script
                result = self.bootstrap('--without-trusttunnel')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.binary.read_bytes(), release.read_bytes())
                self.assertTrue((self.prefix / 'running').exists())
                self.assertFalse((self.prefix / 'bin/trusttunnel_client').exists())

    def test_historical_installer_does_not_fetch_external_client(self):
        # This fixture is the unchanged tools/install.sh from release v0.3.0.
        release = self.release('v0.3.0')
        (release.parent / 'install.sh').write_bytes(
            (ROOT / 'test/install/fixtures/install-external-client.sh').read_bytes())
        self.write_checksums(release.parent)
        for args in ((), ('--without-trusttunnel',)):
            with self.subTest(args=args):
                result = self.install('--version', 'v0.3.0', *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.binary.read_bytes(), release.read_bytes())
                self.assertTrue((self.prefix / 'running').exists())
                self.assertFalse((self.prefix / 'bin/trusttunnel_client').exists())
                self.assertNotIn('TrustTunnel/TrustTunnelClient',
                                 self.requests.read_text())

    def test_explicit_lite_version_skips_main(self):
        self.env['CPU'] = 'mipsel'
        release = self.release('v0.9.0', arch='mipsle', lite=True)
        result = self.install('--version', '0.9.0', '--lite')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.binary.read_bytes(), release.read_bytes())
        self.assert_release('v0.9.0', variant='lite')
        self.assertNotIn('/main/version.txt', self.requests.read_text())
        self.assertNotIn('/releases/latest', self.requests.read_text())

    def test_default_ignores_unpublished_main_version(self):
        stable = self.release('v1.2.3')
        (self.mirror / 'version.txt').write_text('1.2.4\n')

        self.assert_panel_access(self.install())
        self.assertEqual(self.binary.read_bytes(), stable.read_bytes())
        self.assertNotIn('/main/version.txt', self.requests.read_text())
        self.assertEqual(self.requests.read_text().count('/releases/latest'), 1)

    def test_default_rejects_unexpected_latest_redirect(self):
        self.release('v1.2.3')
        (self.mirror / 'latest').write_text('https://example.com/releases/tag/v1.2.3')

        result = self.install()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unexpected latest release URL', result.stderr)
        self.assertFalse(self.binary.exists())

    def test_bad_checksum_keeps_running_release(self):
        first = self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        corrupt = self.release('v1.2.4')
        (corrupt.parent / 'bootstrap.sh').write_text('exit 0\n')
        self.write_checksums(corrupt.parent)
        corrupt.write_text('bad download')
        result = self.install('--version', 'v1.2.4')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA256', result.stderr)
        self.assertNotIn('/bootstrap.sh', self.requests.read_text())
        self.assertEqual(self.binary.read_bytes(), first.read_bytes())
        self.assertTrue((self.prefix / 'running').exists())

    def test_entware_preflight_rejects_changed_staged_binary(self):
        first = self.release('v1.2.3', stop='touch "$KEENPROXY_PREFIX/stopped"; rm -f "$state"')
        self.assert_panel_access(self.install())
        folder = self.release('v1.2.4').parent
        self.executable(folder / 'install.sh', '''
mkdir -p "$2/bin"
printf '#!/bin/sh\\nexit 0\\n' > "$4"
cp "$4" "$2/bin/keenproxy"
chmod 755 "$2/bin/keenproxy"
''')
        self.write_checksums(folder)

        result = self.install('--version', 'v1.2.4')

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('staged binary differs from the verified release', result.stderr)
        self.assertFalse((self.prefix / 'stopped').exists())
        self.assertEqual(self.binary.read_bytes(), first.read_bytes())
        self.assert_release('v1.2.3')

    def test_partial_rollback_retains_all_original_files(self):
        first = self.release('v1.2.3')
        self.assert_panel_access(self.install())
        service = self.service.read_bytes()
        release = self.release_record.read_bytes()
        self.release('v1.2.4', start=False)
        self.command('mv', '''
for path in "$@"; do target=$path; done
if [ "$target" = "$KEENPROXY_PREFIX/etc/init.d/S99keenproxy" ] &&
    [ -f "$KEENPROXY_PREFIX/controller-replaced" ]; then
    exit 1
elif [ "$target" = "$KEENPROXY_PREFIX/etc/init.d/S99keenproxy" ]; then
    touch "$KEENPROXY_PREFIX/controller-replaced"
fi
exec /bin/mv "$@"
''')

        result = self.install('--version', 'v1.2.4')

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('rollback failed; recovery files retained', result.stderr)
        (work,) = (self.prefix / 'tmp').glob('keenproxy-release.*')
        previous = work / 'previous'
        self.assertEqual((previous / 'bin/keenproxy').read_bytes(), first.read_bytes())
        self.assertEqual((previous / 'etc/init.d/S99keenproxy').read_bytes(), service)
        self.assertEqual((previous / 'share/keenproxy/release').read_bytes(), release)
        self.assertEqual(self.binary.read_bytes(), first.read_bytes())

    def test_failed_start_restores_previous_release(self):
        first = self.release('v1.2.3')
        installed = self.install()
        self.assert_panel_access(installed)
        before = (self.prefix / 'url-invocations').read_text()
        folder = self.release('v1.2.4', start=False).parent
        (folder / 'bootstrap.sh').write_text('exit 0\n')
        self.write_checksums(folder)
        result = self.install('--version', 'v1.2.4')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('/bootstrap.sh', self.requests.read_text())
        self.assertNotIn('Access URL:', result.stdout)
        self.assertNotIn('Retrieve existing panel token:', result.stdout)
        self.assertEqual((self.prefix / 'url-invocations').read_text(), before)
        self.assertEqual(self.binary.read_bytes(), first.read_bytes())
        self.assert_release('v1.2.3')
        self.assertTrue((self.prefix / 'running').exists())

    def test_expected_release_guards_updates_and_downgrades(self):
        first = self.release('v1.2.3')
        second = self.release('v1.2.4')
        self.assertEqual(self.install().returncode, 0)
        before = self.requests.read_bytes()
        for expected in ('v1.2.2', 'v1.2.3\nv1.2.2'):
            result = self.install('--version', 'v1.2.4', '--expect-current', expected)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.requests.read_bytes(), before)
            self.assertEqual(self.binary.read_bytes(), first.read_bytes())
            self.assert_release('v1.2.3')
        result = self.install('--version', 'v1.2.4', '--expect-current', 'v1.2.3')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.binary.read_bytes(), second.read_bytes())
        result = self.install('--version', 'v1.2.3', '--expect-current', 'v1.2.4')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.binary.read_bytes(), first.read_bytes())
        self.assert_release('v1.2.3', 'v1.2.4')

    def test_variant_switch_records_exact_previous_build_and_rejects_stale_job(self):
        first = self.release('v1.2.3')
        lite = self.release('v1.2.4', lite=True)
        self.assert_panel_access(self.install())
        self.assert_panel_access(self.install('--version', 'v1.2.4', '--lite'))
        self.assertEqual(self.binary.read_bytes(), lite.read_bytes())
        self.assertEqual(self.release_record.read_text(),
                         'current v1.2.4\nprevious v1.2.3\nvariant lite\nprevious_variant full\n')
        before = self.requests.read_bytes()
        result = self.install('--version', 'v1.2.3', '--expect-current', 'v1.2.4',
                              '--expect-variant', 'full')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('installed variant changed', result.stderr)
        self.assertEqual(self.requests.read_bytes(), before)
        self.assertEqual(self.binary.read_bytes(), lite.read_bytes())
        self.assert_panel_access(self.install('--version', 'v1.2.3', '--expect-current',
                                              'v1.2.4', '--expect-variant', 'lite'))
        self.assertEqual(self.binary.read_bytes(), first.read_bytes())
        self.assertEqual(self.release_record.read_text(),
                         'current v1.2.3\nprevious v1.2.4\nvariant full\nprevious_variant lite\n')
        same_tag_lite = first.with_name('keenproxy-lite-linux-arm64')
        same_tag_lite.write_bytes(first.read_bytes() + b'\n# lite\n')
        self.write_checksums(first.parent)
        self.assert_panel_access(self.install('--version', 'v1.2.3', '--lite'))
        self.assertEqual(self.binary.read_bytes(), same_tag_lite.read_bytes())
        self.assert_release('v1.2.3', 'v1.2.4', 'lite')

    def test_arm64_kernel_with_32_bit_userspace_selects_armv5_asset(self):
        self.env['ELF_HEADER'] = '7f454c460101'
        release = self.release('v1.2.3', arch='armv5', lite=True)
        self.assert_panel_access(self.install('--lite'))
        self.assertEqual(self.binary.read_bytes(), release.read_bytes())
        self.assertIn('/v1.2.3/keenproxy-lite-linux-armv5', self.requests.read_text())

    def test_expected_release_requires_managed_version_metadata(self):
        result = self.install('--version', 'v1.2.4', '--expect-current', 'v1.2.3')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.requests.exists())
        self.assertFalse(self.binary.exists())
        self.assertFalse(self.release_record.exists())

    def test_missing_assets_and_unknown_cpu_leave_existing_files(self):
        first = self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        self.assertNotEqual(self.install('--version', 'v1.2.4').returncode, 0)
        self.env['CPU'] = 'riscv64'
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(self.binary.read_bytes(), first.read_bytes())
        self.assertTrue((self.prefix / 'running').exists())

    def test_unmanaged_process_is_left_alone(self):
        self.release('v1.2.3')
        self.executable(self.binary, 'echo old')
        self.command('pidof', 'echo 1234')
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unmanaged', result.stderr)
        self.assertIn('echo old', self.binary.read_text())
        self.assertFalse(self.config.exists())

    def test_dry_run_does_not_print_credentials(self):
        self.release('v1.2.3', dry_run='echo synthetic-password >&2; exit 1')
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('failed validation', result.stderr)
        self.assertNotIn('synthetic-password', result.stdout + result.stderr)

    def test_successful_dry_run_does_not_print_credentials(self):
        self.release('v1.2.3', dry_run='echo synthetic-password; echo "# jumps"; exit 0')
        result = self.install()
        self.assert_panel_access(result)
        self.assertNotIn('synthetic-password', result.stdout + result.stderr)

    def test_upgrade_refuses_to_replace_files_during_service_action(self):
        first = self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        self.release('v1.2.4')
        lock = self.prefix / 'var/run/keenproxy/action.lock'
        lock.mkdir(parents=True)
        result = self.install('--version', 'v1.2.4')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('service action already in progress', result.stderr)
        self.assertEqual(self.binary.read_bytes(), first.read_bytes())
        self.assertTrue((self.prefix / 'running').exists())
        self.assertTrue(lock.is_dir())


class SpacedPrefixBootstrapTest(BootstrapFixture):
    prefix_name = 'opt dir'

    def test_access_command_quotes_paths_with_spaces(self):
        self.release('v1.2.3')
        result = self.install()
        self.assert_panel_access(result)
        self.assertIn(' ', str(self.prefix))
        self.assertIn(f"'{self.prefix}/bin/keenproxy'", result.stdout)
        self.assertIn(f"'{self.config}'", result.stdout)
        self.assert_url_queries(1)
