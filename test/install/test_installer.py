"""Exercise the binary-only installer inside an isolated prefix."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'tools/install.sh'


class InstallerTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.prefix = self.root / 'opt'
        self.source = self.root / 'keenproxy'
        self.source.write_text('#!/bin/sh\nexit 0\n')
        self.source.chmod(0o755)

    def run_install(self, *args):
        return subprocess.run(
            ['sh', str(SCRIPT), '--prefix', str(self.prefix), *args],
            capture_output=True, text=True, timeout=10)

    def test_installs_embedded_engine_without_downloading_external_client(self):
        config = self.prefix / 'etc/keenproxy/config.yaml'
        config.parent.mkdir(parents=True)
        config.write_text('user configuration')
        client = self.prefix / 'bin/trusttunnel_client'
        client.parent.mkdir()
        client.write_text('independently installed client')
        commands = self.root / 'commands'
        commands.mkdir()
        marker = self.root / 'network-used'
        curl = commands / 'curl'
        curl.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 1\n')
        curl.chmod(0o755)
        result = subprocess.run(
            ['sh', str(SCRIPT), '--prefix', str(self.prefix), '--binary', str(self.source)],
            env={**os.environ, 'PATH': f'{commands}:{os.environ["PATH"]}'},
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = self.prefix / 'bin/keenproxy'
        self.assertEqual(installed.read_bytes(), self.source.read_bytes())
        self.assertTrue(os.access(installed, os.X_OK))
        self.assertEqual(config.read_text(), 'user configuration')
        self.assertEqual(client.read_text(), 'independently installed client')
        self.assertFalse(marker.exists())
        self.assertEqual(list((self.prefix / 'tmp').iterdir()), [])

    def test_missing_binary_preserves_installed_application(self):
        installed = self.prefix / 'bin/keenproxy'
        installed.parent.mkdir(parents=True)
        installed.write_text('old application')
        result = self.run_install('--binary', str(self.root / 'missing'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(installed.read_text(), 'old application')

    def test_non_executable_source_is_rejected(self):
        self.source.chmod(0o644)
        result = self.run_install('--binary', str(self.source))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.prefix / 'bin/keenproxy').exists())


if __name__ == '__main__':
    unittest.main()
