"""Contract for the local and CI secret scan."""
import hashlib
import os
from pathlib import Path
import platform
import stat
import subprocess
import tarfile
import tempfile
import textwrap
import urllib.request
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'tools/scan-secrets.sh'
WORKFLOW = ROOT / '.github/workflows/ci.yml'
HEAD = 'b' * 40
LINUX_SHA256 = '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'
DARWIN_ARM64_SHA256 = 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5'
SCANNER_ASSETS = {
    ('Linux', 'x86_64'): ('linux_x64', LINUX_SHA256),
    ('Linux', 'aarch64'): ('linux_arm64', 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080'),
    ('Darwin', 'arm64'): ('darwin_arm64', DARWIN_ARM64_SHA256),
    ('Darwin', 'x86_64'): ('darwin_x64', 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709'),
}


class SecretScanTest(unittest.TestCase):
    scanner = None

    @classmethod
    def setUpClass(cls):
        # One checksum-verified binary for every live scan. make test must not
        # download the release once per assertion.
        if os.environ.get('GITLEAKS_BIN'):
            cls.scanner = os.environ['GITLEAKS_BIN']
            return
        asset, digest = SCANNER_ASSETS[(platform.system(), platform.machine())]
        tmp = tempfile.TemporaryDirectory(prefix='gitleaks-test-')
        # Registered before the download so a failed setUpClass still cleans up.
        cls.addClassCleanup(tmp.cleanup)
        cache = Path(tmp.name)
        archive = cache / 'gitleaks.tar.gz'
        url = f'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_{asset}.tar.gz'
        urllib.request.urlretrieve(url, archive)
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != digest:
            raise AssertionError(f'gitleaks checksum mismatch for {asset}')
        with tarfile.open(archive) as tar:
            tar.extract('gitleaks', cache)
        binary = cache / 'gitleaks'
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        cls.scanner = str(binary)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.stub = self.root / 'gitleaks'
        self.args = self.root / 'args'
        self.stub.write_text(textwrap.dedent(f'''\
            #!/bin/sh
            printf '%s\\n' "$@" > "{self.args}"
            exit "${{GITLEAKS_EXIT:-0}}"
            '''))
        self.stub.chmod(self.stub.stat().st_mode | stat.S_IEXEC)
        self.env = dict(os.environ, GITLEAKS_BIN=str(self.stub))

    def run_scan(self, *args, cwd=None):
        return subprocess.run(
            [str(SCRIPT), *args],
            cwd=cwd or self.root,
            env=self.env,
            text=True,
            capture_output=True,
        )

    def test_rejects_missing_mode_without_running_scanner(self):
        result = self.run_scan()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('history', result.stderr)
        self.assertFalse(self.args.exists())

    def test_rejects_non_sha_range_without_running_scanner(self):
        result = self.run_scan('range', 'not-a-sha', HEAD)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.args.exists())

    def test_history_scans_only_commits_reachable_from_head(self):
        self.git(self.root, 'init', '-q', '-b', 'main')
        self.commit_file(self.root, 'clean.txt', 'clean\n', 'base')
        result = self.run_scan('history')
        self.assertEqual(result.returncode, 0, result.stderr)
        recorded = self.args.read_text()
        self.assertIn('--log-opts=--diff-merges=first-parent HEAD\n', recorded)
        self.assertIn('--redact\n', recorded)
        self.assertNotIn('--all', recorded)

    def test_range_scans_commits_reachable_from_head_but_not_base(self):
        self.git(self.root, 'init', '-q', '-b', 'main')
        base = self.commit_file(self.root, 'clean.txt', 'clean\n', 'base')
        head = self.commit_file(self.root, 'next.txt', 'next\n', 'next')
        result = self.run_scan('range', base, head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'--log-opts=--diff-merges=first-parent {base}..{head}\n', self.args.read_text())

    def test_scanner_failure_fails_the_check(self):
        self.git(self.root, 'init', '-q', '-b', 'main')
        self.commit_file(self.root, 'clean.txt', 'clean\n', 'base')
        self.env['GITLEAKS_EXIT'] = '1'
        result = self.run_scan('history')
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_rejects_archive_whose_checksum_does_not_match(self):
        commands = self.root / 'bin'
        commands.mkdir()
        marker = self.root / 'executed'
        archive = self.root / 'bad.tar.gz'
        payload = self.root / 'gitleaks-payload'
        payload.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
        payload.chmod(payload.stat().st_mode | stat.S_IEXEC)
        with tarfile.open(archive, 'w:gz') as tar:
            tar.add(payload, arcname='gitleaks')
        curl = commands / 'curl'
        curl.write_text(textwrap.dedent(f'''\
            #!/bin/sh
            while [ "$#" -gt 0 ]; do
                if [ "$1" = "-o" ]; then
                    cp "{archive}" "$2"
                    exit 0
                fi
                shift
            done
            exit 22
            '''))
        curl.chmod(curl.stat().st_mode | stat.S_IEXEC)
        self.git(self.root, 'init', '-q', '-b', 'main')
        self.commit_file(self.root, 'clean.txt', 'clean\n', 'base')
        env = dict(os.environ, PATH=f'{commands}:{os.environ["PATH"]}')
        env.pop('GITLEAKS_BIN', None)
        result = subprocess.run(
            [str(SCRIPT), 'history'], cwd=self.root, env=env, text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists(), result.stderr)

    def test_pinned_release_checksums_are_the_verified_assets(self):
        script = SCRIPT.read_text()
        self.assertIn('8.30.1', script)
        self.assertIn(LINUX_SHA256, script)
        self.assertIn(DARWIN_ARM64_SHA256, script)

    def merge_canary(self):
        # Assemble the fixture at runtime. A committed keyword plus value is
        # itself a finding, and the pull-request scan reads every commit.
        parts = ['q83v', 'E3mN7kP2', 'sL9wR4tY6uI1oA5dF8gH0jK3lZ7xC2b=']
        return 'private' + '_key: ' + ''.join(parts) + '\n'

    def git(self, repo, *args):
        subprocess.run(
            ['git', '-C', str(repo), '-c', 'user.email=test@example.com', '-c', 'user.name=test', *args],
            check=True, capture_output=True, text=True,
        )

    def commit_file(self, repo, name, text, message):
        (repo / name).write_text(text)
        self.git(repo, 'add', name)
        self.git(repo, 'commit', '-q', '-m', message)
        return self.git_stdout(repo, 'rev-parse', 'HEAD')

    def git_stdout(self, repo, *args):
        result = subprocess.run(
            ['git', '-C', str(repo), *args], check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()

    def real_scan(self, repo, *args):
        env = dict(os.environ, GITLEAKS_BIN=self.scanner)
        return subprocess.run(
            [str(SCRIPT), *args], cwd=repo, env=env, text=True, capture_output=True,
        )

    def test_missing_revision_is_not_a_clean_range(self):
        repo = self.root / 'repo'
        repo.mkdir()
        self.git(repo, 'init', '-q', '-b', 'main')
        head = self.commit_file(repo, 'clean.txt', 'clean\n', 'base')
        missing = 'f' * 40
        result = self.real_scan(repo, 'range', missing, head)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        empty = self.real_scan(repo, 'range', head, head)
        self.assertEqual(empty.returncode, 0, empty.stdout + empty.stderr)

    def test_merge_only_credential_fails_both_scans_without_reading_other_branches(self):
        repo = self.root / 'repo'
        repo.mkdir()
        self.git(repo, 'init', '-q', '-b', 'main')
        self.commit_file(repo, 'clean.txt', 'clean\n', 'base')
        self.git(repo, 'checkout', '-q', '-b', 'side')
        self.commit_file(repo, 'side.txt', 'side\n', 'side')
        self.git(repo, 'checkout', '-q', 'main')
        first_parent = self.git_stdout(repo, 'rev-parse', 'HEAD')
        self.git(repo, 'merge', '-q', '--no-ff', 'side', '-m', 'merge')
        canary = self.merge_canary()
        self.assertNotIn(canary, Path(__file__).read_text())
        (repo / 'secret.yaml').write_text(canary)
        self.git(repo, 'add', 'secret.yaml')
        self.git(repo, 'commit', '-q', '--amend', '--no-edit')
        merge = self.git_stdout(repo, 'rev-parse', 'HEAD')
        self.git(repo, 'checkout', '-q', '-b', 'unmerged', first_parent)
        self.commit_file(repo, 'other.yaml', canary, 'unmerged secret')
        self.git(repo, 'checkout', '-q', 'main')
        history = self.real_scan(repo, 'history')
        self.assertNotEqual(history.returncode, 0, history.stdout + history.stderr)
        ranged = self.real_scan(repo, 'range', first_parent, merge)
        self.assertNotEqual(ranged.returncode, 0, ranged.stdout + ranged.stderr)
        self.git(repo, 'checkout', '-q', first_parent)
        untouched = self.real_scan(repo, 'history')
        self.assertEqual(untouched.returncode, 0, untouched.stdout + untouched.stderr)

    def test_ci_runs_a_branch_scan_and_a_main_history_scan(self):
        workflow = WORKFLOW.read_text()
        self.assertNotIn('uses: gitleaks/gitleaks-action', workflow)
        self.assertNotIn('GITLEAKS_LICENSE', workflow)
        branch = workflow.split('secrets-branch:', 1)[1].split('\n  secrets-history:', 1)[0]
        history = workflow.split('secrets-history:', 1)[1]
        self.assertIn("github.event_name == 'pull_request'", branch)
        self.assertIn('tools/scan-secrets.sh range', branch)
        self.assertIn('fetch-depth: 0', branch)
        self.assertIn('persist-credentials: false', branch)
        self.assertIn("github.ref == 'refs/heads/main'", history)
        self.assertIn('tools/scan-secrets.sh history', history)
        self.assertIn('fetch-depth: 0', history)
        self.assertIn('persist-credentials: false', history)
