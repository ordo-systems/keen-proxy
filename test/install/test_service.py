"""Exercise the actual Entware controller with isolated Linux processes."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from test_bootstrap import BootstrapFixture, ROOT

CONTROLLER = ROOT / 'tools/S99keenproxy'
FIXTURES = Path(__file__).parent / 'fixtures'
# Unchanged service asset from release v0.9.1.
LEGACY_CONTROLLER = FIXTURES / 'S99keenproxy-v0.9.1'


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux /proc/PID/exe')
class ServiceTest(BootstrapFixture):
    @classmethod
    def setUpClass(cls):
        build = tempfile.TemporaryDirectory()
        cls.addClassCleanup(build.cleanup)
        source = FIXTURES / 'service_daemon.c'
        cls.daemon = Path(build.name) / 'daemon'
        cls.broken_daemon = Path(build.name) / 'broken-daemon'
        cls.legacy_daemon = Path(build.name) / 'legacy-daemon'
        for binary, flags in [(cls.daemon, []), (cls.broken_daemon, ['-DFAIL_START']),
                              (cls.legacy_daemon, ['-DLEGACY_STARTUP'])]:
            subprocess.run(['cc', *flags, str(source), '-o', str(binary)],
                           check=True, timeout=30)

    def setUp(self):
        super().setUp()
        self.env.pop('KEENPROXY_SERVICE_LOCK_TOKEN', None)
        self.pids = self.root / 'daemon-pids'
        self.pids.touch()
        self.env.update(FIXTURE_PIDS=str(self.pids), FIXTURE_READY='no',
                        FIXTURE_STARTUP_STATE='active')
        self.addCleanup(self.stop_fixture_processes)
        self.state = self.prefix / 'var/run/keenproxy'
        self.startup_state = self.state / 'startup-state'
        self.pidfile = self.state / 'pid'
        self.lock = self.state / 'action.lock'
        shutil.copy2(self.daemon, self.binary)
        # Keep real sleeps for process scheduling but shorten readiness timeouts.
        self.command('sleep', 'exec /bin/sleep 0.1')
        self.executable(self.prefix / 'sbin/iptables', '''
case "$*" in
    "-t nat -S") exit 0 ;;
    *"-t nat -C PREROUTING -j KEENPROXY_DNS") [ "$FIXTURE_READY" = yes ] ;;
    "-w -t filter -I FORWARD "*|"-w -t filter -D FORWARD "*) exit 0 ;;
    *) exit 1 ;;
esac''')

    def stop_fixture_processes(self):
        """Reclaim fixture processes even if a failed assertion leaves no pidfile."""
        paths = (str(self.binary), f'{self.binary} (deleted)')
        pids = [pid for pid in map(int, self.pids.read_text().splitlines())
                if self.process_executable(pid) in paths]
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 3
        while pids and time.monotonic() < deadline:
            pids = [pid for pid in pids if self.process_executable(pid) in paths]
            if pids:
                time.sleep(0.01)
        self.assertFalse(pids, f'fixture processes remained: {pids}')

    @staticmethod
    def process_executable(pid):
        try:
            return os.readlink(f'/proc/{pid}/exe')
        except FileNotFoundError:
            return None

    def action(self, name, *, controller=CONTROLLER, token=None):
        env = self.env.copy()
        if token is not None:
            env['KEENPROXY_SERVICE_LOCK_TOKEN'] = token
        return subprocess.run(['sh', str(controller), name], env=env,
                              capture_output=True, text=True, timeout=15)

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)

    def running_pid(self):
        pid = int(self.pidfile.read_text())
        self.assertEqual(self.process_executable(pid), str(self.binary))
        return pid

    def test_start_is_idempotent_and_restart_replaces_the_process(self):
        self.assert_success(self.action('start'))
        first = self.running_pid()
        self.assertEqual(self.startup_state.read_text(), f'active {first}\n')
        self.assert_success(self.action('start'))
        self.assertEqual(self.running_pid(), first)
        self.assert_success(self.action('restart'))
        second = self.running_pid()
        self.assertNotEqual(first, second)
        self.assertIsNone(self.process_executable(first))
        self.assert_success(self.action('stop'))
        self.assertIsNone(self.process_executable(second))
        self.assertFalse(self.pidfile.exists())
        self.assertNotEqual(self.action('status').returncode, 0)
        self.assertFalse(self.lock.exists())

    def test_foreign_pid_is_never_treated_as_the_managed_process(self):
        with subprocess.Popen(['/bin/sleep', '30']) as other:
            try:
                self.state.mkdir(parents=True)
                self.pidfile.write_text(f'{other.pid}\n')
                self.assertNotEqual(self.action('check').returncode, 0)
                self.command('pidof', f'echo {other.pid}')
                self.assertIn('unmanaged process', self.action('start').stderr)
                self.assert_success(self.action('stop'))
                self.assertIsNone(other.poll())
                self.assertFalse(self.pidfile.exists())
            finally:
                other.terminate()

    def test_only_the_installer_lock_owner_can_delegate_actions(self):
        self.lock.mkdir(parents=True)
        owner = self.lock / 'owner'
        owner.write_text('installer\n')
        self.assertIn('already in progress', self.action('start').stderr)
        self.assertIn('invalid installer lock', self.action('start', token='wrong').stderr)
        self.assertFalse(self.pidfile.exists())
        self.assert_success(self.action('start', token='installer'))
        pid = self.running_pid()
        self.assert_success(self.action('stop', token='installer'))
        self.assertIsNone(self.process_executable(pid))
        self.assertEqual(owner.read_text(), 'installer\n')

    def test_management_only_start_requires_the_managed_pid_and_cleans_up(self):
        self.env['FIXTURE_STARTUP_STATE'] = 'management-only'
        self.assert_success(self.action('start'))
        pid = self.running_pid()
        self.assertEqual(self.startup_state.read_text(), f'management-only {pid}\n')
        self.assert_success(self.action('start'))
        self.assertEqual(self.running_pid(), pid)
        self.assert_success(self.action('stop'))
        self.assertIsNone(self.process_executable(pid))
        self.assertFalse(self.startup_state.exists())

    def test_residual_firewall_jump_cannot_make_an_unready_daemon_ready(self):
        self.env['FIXTURE_READY'] = 'yes'
        self.env.pop('FIXTURE_STARTUP_STATE')
        self.state.mkdir(parents=True)
        for index, mode in enumerate(('missing', 'wrong-pid'), start=1):
            with self.subTest(marker=mode):
                self.startup_state.write_text('active 42\n')
                if mode == 'wrong-pid':
                    self.env['FIXTURE_STARTUP_STATE'] = mode
                result = self.action('start')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('startup failed', result.stderr)
                pids = self.pids.read_text().splitlines()
                self.assertEqual(len(pids), index)
                self.assertIsNone(self.process_executable(pids[-1]))
                self.assertFalse(self.pidfile.exists())
                self.assertFalse(self.startup_state.exists())
                self.assertFalse(self.lock.exists())

    def publish(self, tag, daemon, controller=CONTROLLER):
        asset = self.release(tag)
        shutil.copyfile(daemon, asset)
        shutil.copy2(controller, asset.with_name('S99keenproxy'))
        self.write_checksums(asset.parent)

    def test_historical_updater_using_a_staged_controller_can_restart_legacy_binary(self):
        self.binary.unlink()
        self.env['FIXTURE_READY'] = 'yes'
        self.publish('v1.2.3', self.legacy_daemon, LEGACY_CONTROLLER)
        self.assert_success(self.install())
        original = self.running_pid()
        self.publish('v1.2.4', self.broken_daemon)
        self.bootstrap_script = FIXTURES / 'bootstrap-external-client.sh'
        result = self.install('--version', 'v1.2.4', '--without-trusttunnel')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('new service failed to start', result.stderr)
        self.assertIn('restoring the previous installation', result.stderr)
        self.assertEqual(self.binary.read_bytes(), self.legacy_daemon.read_bytes())
        self.assertEqual(self.service.read_bytes(), LEGACY_CONTROLLER.read_bytes())
        self.assertFalse(self.startup_state.exists())
        self.assert_success(self.action('status', controller=self.service))
        self.assertNotEqual(self.running_pid(), original)
        self.assertIsNone(self.process_executable(original))
        self.assertFalse(self.lock.exists())

    def test_failed_downgrade_restarts_parked_release_with_its_restored_controller(self):
        self.binary.unlink()
        self.env['FIXTURE_STARTUP_STATE'] = 'management-only'
        self.publish('v1.2.4', self.daemon)
        self.assert_success(self.install('--version', 'v1.2.4'))
        original = self.running_pid()
        self.publish('v1.2.3', self.legacy_daemon, LEGACY_CONTROLLER)

        result = self.install('--version', 'v1.2.3', '--expect-current', 'v1.2.4')

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('new service failed to start', result.stderr)
        self.assertIn('restoring the previous installation', result.stderr)
        self.assertEqual(self.binary.read_bytes(), self.daemon.read_bytes())
        self.assertEqual(self.service.read_bytes(), CONTROLLER.read_bytes())
        restored = self.running_pid()
        self.assertNotEqual(restored, original)
        self.assertIsNone(self.process_executable(original))
        self.assertEqual(self.startup_state.read_text(), f'management-only {restored}\n')
        self.assertFalse(self.lock.exists())
