"""Native release transactions against an isolated OpenWrt filesystem."""
import subprocess
import unittest

from test_bootstrap import BootstrapFixture, ROOT


class NativeFixture(BootstrapFixture):
    prefix_name = 'openwrt'

    def setUp(self):
        super().setUp()
        self.env['KEENPROXY_PLATFORM'] = 'openwrt'
        (self.prefix / 'etc/init.d/rc.unslung').unlink()
        for directory in ('usr/bin', 'usr/sbin', 'usr/share/keenproxy', 'etc/rc.d'):
            (self.prefix / directory).mkdir(parents=True, exist_ok=True)
        (self.prefix / 'etc/openwrt_release').write_text("DISTRIB_ID='OpenWrt'\n")
        self.executable(self.prefix / 'sbin/procd', 'exit 0')
        for name in ('iptables', 'iptables-restore'):
            self.executable(self.prefix / 'usr/sbin' / name, 'exit 0')
        # rc.common is an external OpenWrt boundary, not an alternative installer.
        self.executable(self.prefix / 'etc/rc.common', '''
service=$1
shift
[ "$service" = "$KEENPROXY_PREFIX/etc/init.d/keenproxy" ] || exit 91
printf '%s %s\\n' "$service" "$*" >> "$KEENPROXY_PREFIX/actions"
. "$service"
case "$1" in
    enabled) test -f "$KEENPROXY_PREFIX/enabled" ;;
    enable) touch "$KEENPROXY_PREFIX/enabled" ;;
    disable) rm -f "$KEENPROXY_PREFIX/enabled" ;;
    *) native_action "$1" ;;
esac
''')
        self.command('hexdump', 'printf "%s" "${ELF_HEADER:-7f454c460201}"')
        self.command('head', '''
case "$*" in
    *'/proc/self/exe'*) printf fixture ;;
    *) exec /usr/bin/head "$@" ;;
esac''')
        self.command('grep', '''
case "$*" in
    *'/proc/cpuinfo'*) [ "${SSE2:-1}" = 1 ]; exit ;;
    *) exec /usr/bin/grep "$@" ;;
esac''')

    @property
    def binary(self):
        return self.prefix / 'usr/bin/keenproxy'

    @property
    def service(self):
        return self.prefix / 'etc/init.d/keenproxy'

    @property
    def release_record(self):
        return self.prefix / 'usr/share/keenproxy/release'

    def release(self, tag, **kwargs):
        binary = super().release(tag, **kwargs)
        self.executable(binary.parent / 'keenproxy.openwrt', '''# KeenProxy OpenWrt service
native_action() {
    state="$KEENPROXY_PREFIX/running"
    case "$1" in
        start) "$KEENPROXY_PREFIX/usr/bin/keenproxy" --fixture-start && touch "$state" ;;
        check|status|running) test -f "$state" ;;
        stop) [ ! -f "$KEENPROXY_PREFIX/fail-stop" ] || return 1
              rm -f "$state" ;;
        *) return 2 ;;
    esac
}''')
        self.write_checksums(binary.parent)
        return binary

    def assert_clean(self):
        self.assertFalse((self.prefix / 'var/lock/keenproxy-install.lock').exists())
        self.assertFalse((self.prefix / 'var/run/keenproxy/action.lock').exists())
        self.assertEqual(list((self.prefix / 'usr/share/keenproxy').glob('keenproxy-release.*')), [])

    def assert_installed(self, binary, current='v1.2.3', previous=''):
        self.assertEqual(self.binary.read_bytes(), binary.read_bytes())
        self.assertEqual(self.release_record.read_text(),
                         f'current {current}\nprevious {previous}\nvariant full\n')
        self.assertTrue((self.prefix / 'running').exists())
        self.assert_clean()


class OpenWrtTest(NativeFixture):
    def test_install_update_downgrade_uninstall_preserves_config_and_token(self):
        first = self.release('v1.2.3')
        self.assert_panel_access(self.install())
        self.assert_installed(first)
        self.assertTrue((self.prefix / 'enabled').exists())
        self.assertFalse((self.prefix / 'bin/keenproxy').exists())
        self.assertIn('br-lan', self.config.read_text())
        self.assertIn(f'token_file: {self.config.with_name("token")}', self.config.read_text())
        self.config.write_text('schema_version: 1\n# operator configuration\n')
        token = self.config.with_name('token')
        token.write_text('private token\n')
        second = self.release('v1.2.4')
        self.assertEqual(self.install('--version', 'v1.2.4', '--expect-current', 'v1.2.3').returncode, 0)
        self.assert_installed(second, 'v1.2.4', 'v1.2.3')
        self.assertEqual(self.install('--version', 'v1.2.3', '--expect-current', 'v1.2.4').returncode, 0)
        self.assert_installed(first, 'v1.2.3', 'v1.2.4')
        before = self.requests.read_bytes()
        for _ in range(2):
            result = self.bootstrap('--uninstall')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(self.binary.exists())
            self.assertFalse(self.service.exists())
            self.assertFalse(self.release_record.exists())
            self.assertFalse((self.prefix / 'enabled').exists())
            self.assert_clean()
        self.assertEqual(before, self.requests.read_bytes())
        self.assertEqual(token.read_text(), 'private token\n')
        self.assertEqual(self.config.read_text(), 'schema_version: 1\n# operator configuration\n')

    def test_failed_start_restores_release_running_and_autostart_state(self):
        first = self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        self.release('v1.2.4', start=False)
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                flag = self.prefix / 'enabled'
                if enabled:
                    flag.touch()
                else:
                    flag.unlink(missing_ok=True)
                result = self.install('--version', 'v1.2.4')
                self.assertNotEqual(result.returncode, 0)
                self.assert_installed(first)
                self.assertEqual(flag.exists(), enabled)

    def test_disabled_autostart_stays_disabled_on_successful_update(self):
        self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        (self.prefix / 'enabled').unlink()
        self.release('v1.2.4')
        result = self.install('--version', 'v1.2.4')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.prefix / 'enabled').exists())

    def test_missing_and_corrupt_native_asset_fail_before_replacement(self):
        first = self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        candidate = self.release('v1.2.4')
        service = candidate.parent / 'keenproxy.openwrt'
        service.write_text('corrupt download')
        before = (self.prefix / 'actions').read_bytes()
        result = self.install('--version', 'v1.2.4')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA256', result.stderr)
        service.unlink()
        self.write_checksums(candidate.parent)
        result = self.install('--version', 'v1.2.4')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.prefix / 'actions').read_bytes(), before)
        self.assert_installed(first)

    def test_native_prerequisites_are_required(self):
        self.release('v1.2.3')
        for name in ('etc/openwrt_release', 'sbin/procd', 'etc/rc.common'):
            with self.subTest(name=name):
                path = self.prefix / name
                saved = path.with_name(path.name + '.saved')
                path.rename(saved)
                try:
                    self.assertNotEqual(self.install().returncode, 0)
                    self.assertFalse(self.binary.exists())
                finally:
                    saved.rename(path)

    def test_native_identity_and_linked_prerequisites_are_rejected(self):
        self.release('v1.2.3')
        identity = self.prefix / 'etc/openwrt_release'
        identity.write_text("DISTRIB_ID='OtherOS'\n")
        result = self.install()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.binary.exists())
        identity.write_text("DISTRIB_ID='OpenWrt'\n")
        for name in ('etc/openwrt_release', 'sbin/procd', 'etc/rc.common'):
            with self.subTest(name=name):
                path = self.prefix / name
                saved = path.with_name(path.name + '.saved')
                path.rename(saved)
                path.symlink_to(saved)
                try:
                    self.assertNotEqual(self.install().returncode, 0)
                    self.assertFalse(self.binary.exists())
                finally:
                    path.unlink()
                    saved.rename(path)

    def test_prerequisite_directories_fail_before_download(self):
        self.release('v1.2.3')
        for name in ('sbin/procd', 'etc/rc.common'):
            with self.subTest(name=name):
                path = self.prefix / name
                saved = path.with_name(path.name + '.saved')
                path.rename(saved)
                path.mkdir()
                try:
                    result = self.install()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(self.requests.exists())
                    self.assertFalse(self.binary.exists())
                finally:
                    path.rmdir()
                    saved.rename(path)

    def test_foreign_and_symlink_service_are_never_replaced(self):
        self.release('v1.2.3')
        self.service.write_text('# operator service\n')
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.service.read_text(), '# operator service\n')
        self.assertFalse(self.config.exists())
        self.service.unlink()
        target = self.root / 'foreign'
        target.write_text('# KeenProxy OpenWrt service\n')
        self.service.symlink_to(target)
        self.assertNotEqual(self.install().returncode, 0)
        self.assertTrue(self.service.is_symlink())
        self.assertFalse(self.binary.exists())

    def test_stop_failure_never_replaces_or_removes_running_release(self):
        first = self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        self.release('v1.2.4')
        (self.prefix / 'fail-stop').touch()
        for args in (('--version', 'v1.2.4'), ('--uninstall',)):
            result = self.install(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assert_installed(first)
            self.assertTrue((self.prefix / 'enabled').exists())

    def test_failed_uninstall_restores_payload_and_autostart(self):
        first = self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        self.command('rm', '''
for path in "$@"; do
    [ "$path" != "$KEENPROXY_PREFIX/etc/init.d/keenproxy" ] || exit 1
done
exec /bin/rm "$@"''')
        result = self.bootstrap('--uninstall')
        self.assertNotEqual(result.returncode, 0)
        self.assert_installed(first)
        self.assertTrue((self.prefix / 'enabled').exists())

    def test_transactions_never_stage_native_payload_on_tmpfs(self):
        self.release('v1.2.3')
        self.command('mktemp', '''
case "$*" in
    *"$KEENPROXY_PREFIX/tmp/"*|*"$KEENPROXY_PREFIX/var/"*) exit 93 ;;
esac
exec /usr/bin/mktemp "$@"''')
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_clean()

    def test_expected_current_is_checked_before_download(self):
        self.release('v1.2.3')
        result = self.install('--version', 'v1.2.3', '--expect-current', 'v1.2.2')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.requests.exists())


class NativeSafetyTest(NativeFixture):
    def test_auto_detection_selects_native_but_keeps_managed_entware(self):
        self.release('v1.2.3')
        del self.env['KEENPROXY_PLATFORM']
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.binary.exists())
        self.executable(self.prefix / 'etc/init.d/rc.unslung', 'exit 0')
        self.executable(self.prefix / 'etc/init.d/S99keenproxy',
                        '# KeenProxy Entware service\nexit 1')
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.prefix / 'bin/keenproxy').exists())

    def test_action_and_installer_locks_leave_existing_release_intact(self):
        first = self.release('v1.2.3')
        self.assertEqual(self.install().returncode, 0)
        self.release('v1.2.4')
        for relative in ('var/run/keenproxy/action.lock', 'var/lock/keenproxy-install.lock'):
            with self.subTest(lock=relative):
                lock = self.prefix / relative
                lock.mkdir(parents=True)
                try:
                    result = self.install('--version', 'v1.2.4')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(lock.exists())
                    self.assertEqual(self.binary.read_bytes(), first.read_bytes())
                finally:
                    lock.rmdir()

    def test_native_candidate_validation_hides_credentials(self):
        self.release('v1.2.3', dry_run='echo private-credential >&2; exit 1')
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('private-credential', result.stdout + result.stderr)
        self.assertFalse(self.binary.exists())
        self.assertFalse(self.config.exists())
        self.assert_clean()

    def test_symlink_binary_and_config_leave_target_untouched(self):
        self.release('v1.2.3')
        target = self.root / 'operator-file'
        target.write_text('operator content\n')
        for path in (self.binary, self.config):
            with self.subTest(path=path):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(target)
                try:
                    self.assertNotEqual(self.install().returncode, 0)
                    self.assertTrue(path.is_symlink())
                    self.assertEqual(target.read_text(), 'operator content\n')
                finally:
                    path.unlink()


class ArchitectureTest(NativeFixture):
    def test_all_native_and_entware_assets_full_and_lite(self):
        cases = [('x86_64', 'amd64', '7f454c460201'),
                 ('x86_64', '386', '7f454c460101'),
                 ('i686', '386', '7f454c460101'),
                 ('armv7l', 'armv5', '7f454c460101'),
                 ('aarch64', 'arm64', '7f454c460201'),
                 ('mipsel', 'mipsle', '7f454c460101'),
                 ('mips', 'mipsle', '7f454c460101'),
                 ('mips', 'mipsbe', '7f454c460102')]
        for platform in ('openwrt', 'entware'):
            self.env['KEENPROXY_PLATFORM'] = platform
            self.executable(self.prefix / 'etc/init.d/rc.unslung', 'exit 0')
            for index, (cpu, suffix, header) in enumerate(cases):
                for lite in (False, True):
                    with self.subTest(platform=platform, cpu=cpu, suffix=suffix, lite=lite):
                        tag = f'v2.{index}.{int(lite)}'
                        folder = self.mirror / tag
                        if not folder.exists():
                            self.release(tag, arch=suffix, lite=lite)
                        self.env.update(CPU=cpu, ELF_HEADER=header)
                        args = ['--version', tag] + (['--lite'] if lite else [])
                        result = self.install(*args)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        asset = f'keenproxy-{"lite-" if lite else ""}linux-{suffix}'
                        self.assertIn('/' + asset, self.requests.read_text())

    def test_unknown_cpu_and_386_without_sse2_fail_closed(self):
        for cpu, header, sse2 in [('riscv64', '7f454c460201', '1'),
                                  ('i686', '7f454c460101', '0'),
                                  ('x86_64', '7f454c460101', '0')]:
            with self.subTest(cpu=cpu):
                self.env.update(CPU=cpu, ELF_HEADER=header, SSE2=sse2)
                self.assertNotEqual(self.install().returncode, 0)
                self.assertFalse(self.binary.exists())


class ProcdControllerTest(NativeFixture):
    def setUp(self):
        super().setUp()
        self.executable(self.binary, '''
[ "$*" = -startup-state-protocol ] || exit 1
case "$FIXTURE_PROTOCOL" in
    legacy) echo 'flag provided but not defined: -startup-state-protocol' >&2; exit 2 ;;
    *) echo 1 ;;
esac
''')
        self.env['FIXTURE_PROTOCOL'] = 'current'
        self.command('sleep', 'exit 0')
        self.executable(self.prefix / 'usr/sbin/iptables',
                        '[ "$FIXTURE_RESIDUAL_JUMP" = yes ]')
        self.env['FIXTURE_RESIDUAL_JUMP'] = 'no'

    def test_controller_startup_failure_cleans_up_without_recursive_rc_common(self):
        controller = ROOT / 'tools/keenproxy.openwrt'
        self.assertTrue(controller.exists(), 'native procd release asset is required')
        self.command('sleep', 'exit 0')
        result = subprocess.run(
            ['sh', '-c', '''
action=start
. "$1"
procd_running() { return 1; }
procd_open_instance() { :; }
procd_set_param() { :; }
procd_close_instance() { :; }
procd_kill() { echo "killed $1"; }
start_service || exit 94
service_started
''', 'fixture', str(controller)],
            env=self.env, text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('startup failed', result.stderr)
        self.assertIn('killed keenproxy', result.stdout)
        self.assertFalse((self.prefix / 'var/run/keenproxy/action.lock').exists())

    def test_controller_only_accepts_pid_markers_or_the_legacy_firewall_check(self):
        controller = ROOT / 'tools/keenproxy.openwrt'
        marker = self.prefix / 'var/run/keenproxy/startup-state'
        for mode, pid, jump, legacy, ready in (
            ('management-only', 42, False, False, True),
            ('active', 42, False, False, True),
            ('active', 43, True, False, False),
            ('', 42, True, False, False),
            ('', 42, True, True, True),
        ):
            with self.subTest(mode=mode, marker_pid=pid, jump=jump, legacy=legacy):
                self.env['FIXTURE_RESIDUAL_JUMP'] = 'yes' if jump else 'no'
                self.env['FIXTURE_PROTOCOL'] = 'legacy' if legacy else 'current'
                result = subprocess.run(
                    ['sh', '-c', '''
action=start
. "$1"
started=no
procd_running() { [ "$*" = 'keenproxy instance1' ] && [ "$started" = yes ]; }
procd_kill() { echo "killed $1"; }
procd_open_instance() { [ "$1" = instance1 ] || exit 92; }
procd_close_instance() { :; }
procd_set_param() {
    if [ "$1" = env ]; then
        [ "$2" = "KEENPROXY_STARTUP_STATE_FILE=$keenproxy_startup_state" ] || exit 93
    fi
}
ubus() {
    [ "$*" = 'call service list {"name":"keenproxy"}' ] || return 1
    printf '%s\\n' '{"keenproxy":{"instances":{"instance1":{"running":true,"pid":42}}}}'
}
jsonfilter() {
    [ "$*" = '-e @.keenproxy.instances.instance1.pid' ] || return 1
    IFS= read -r input || return 1
    printf '%s\\n' 42
}
readlink() {
    case "$1" in /proc/42/exe|/proc/43/exe) printf '%s\\n' "$keenproxy_binary" ;; esac
}
printf '%s\\n' 'management-only 42' > "$keenproxy_startup_state"
start_service || exit 94
[ ! -e "$keenproxy_startup_state" ] || exit 95
if [ -n "$2" ]; then printf '%s %s\\n' "$2" "$3" > "$keenproxy_startup_state"; fi
started=yes
service_started || exit $?
start_service && service_started && service_stopped
''', 'fixture', str(controller), mode, str(pid)],
                    env=self.env, text=True, capture_output=True, timeout=5)
                if ready:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn('killed keenproxy', result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('startup failed', result.stderr)
                    self.assertIn('killed keenproxy', result.stdout)
                self.assertFalse(marker.exists())
                self.assertFalse(marker.with_name('action.lock').exists())
