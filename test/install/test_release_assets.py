"""Execute release packaging against old and native-capable source fixtures."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/release.yml'


def release_step(name):
    """Run the workflow's shell payload, not a separate packaging implementation."""
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index('      - name: ' + name) + 2
    end = start
    while end < len(lines) and (lines[end].startswith('          ') or not lines[end]):
        end += 1
    return textwrap.dedent('\n'.join(lines[start:end]))


@unittest.skipUnless(sys.platform == 'linux', 'release packaging requires GNU tar')
class ReleaseAssetsTest(unittest.TestCase):
    def test_existing_release_retry_preserves_platform_asset_boundary(self):
        for native in (False, True):
            with self.subTest(native=native), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                tools = root / 'tools'
                dist = root / 'dist'
                tools.mkdir()
                dist.mkdir()
                (root / 'LICENSES').mkdir()
                for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
                    (root / name).write_text('fixture notice\n')
                for name in ('install.sh', 'S99keenproxy'):
                    (tools / name).write_text('fixture controller\n')
                if native:
                    (tools / 'keenproxy.openwrt').write_text('native controller\n')
                else:
                    # An old source tag must not publish a stale native output.
                    (dist / 'keenproxy.openwrt').write_text('stale output\n')
                binaries = {f'keenproxy-{variant}linux-{arch}'
                            for variant in ('', 'lite-')
                            for arch in ('amd64', '386', 'armv5', 'arm64', 'mipsle', 'mipsbe')}
                for name in binaries:
                    (dist / name).write_text('fixture binary\n')
                # Only external source/tool identity and GitHub are simulated.
                # Hashing, archives, payload selection and upload arguments are real.
                boundary = r'''
set -eu
export RELEASE_TAG=v1.2.3
export GH_REPO=example/fixture
export TMPDIR="$PWD"
git() {
    case "$1" in
        archive) tar -cf - --files-from /dev/null ;;
        ls-tree) printf 'version.txt\0' ;;
        show) printf '2026-01-01T00:00:00Z\n' ;;
        rev-parse) printf '0000000000000000000000000000000000000000\n' ;;
        *) return 2 ;;
    esac
}
go() { printf 'fixture go identity\n'; }
node() { printf 'fixture node identity\n'; }
npm() { printf 'fixture npm identity\n'; }
make() { printf 'fixture protocol tags\n'; }
gh() {
    case "$2" in
        view) return 0 ;;
        upload) printf '%s\n' "$4" >> "$PWD/uploaded" ;;
        *) return 2 ;;
    esac
}
'''
                package = release_step('Package source, notices, and build identity')
                upload = release_step('Attach missing assets without overwriting published files')
                script = boundary + '\n(\n' + package + '\n)\n' + upload
                result = subprocess.run(['bash', '-c', script], cwd=root,
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                checksums = {}
                for line in (dist / 'SHA256SUMS').read_text().splitlines():
                    digest, name = line.split()
                    checksums[name] = digest
                    self.assertEqual(digest, hashlib.sha256((dist / name).read_bytes()).hexdigest())
                expected = binaries | {'install.sh', 'S99keenproxy', 'keenproxy-source.tar.gz',
                                       'keenproxy-notices.tar.gz', 'BUILD_INFO.txt'}
                if native:
                    expected.add('keenproxy.openwrt')
                self.assertEqual(set(checksums), expected)
                uploaded = {Path(line).name for line in (root / 'uploaded').read_text().splitlines()}
                self.assertEqual(uploaded, expected | {'SHA256SUMS'})
