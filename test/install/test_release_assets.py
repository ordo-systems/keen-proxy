"""Exercise release packaging and the publish transaction without GitHub writes."""
import hashlib
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/release.yml'
PUBLISH = ROOT / 'tools/publish-release-assets.sh'


def release_step(name):
    """Run the workflow's shell payload, not a separate packaging implementation."""
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index('        run: |', lines.index('      - name: ' + name)) + 1
    end = start
    while end < len(lines) and (lines[end].startswith('          ') or not lines[end]):
        end += 1
    return textwrap.dedent('\n'.join(lines[start:end]))


@unittest.skipUnless(sys.platform == 'linux', 'release packaging requires GNU tar')
class ReleaseAssetsTest(unittest.TestCase):
    def test_release_package_preserves_platform_asset_boundary(self):
        for native, with_sources in ((False, False), (True, False), (True, True)):
            with self.subTest(native=native, with_sources=with_sources), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                tools = root / 'tools'
                dist = root / 'dist'
                tools.mkdir()
                dist.mkdir()
                (root / 'LICENSES').mkdir()
                for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
                    (root / name).write_text('fixture notice\n')
                if with_sources:
                    (root / 'PRESET_SOURCES.md').write_text('preset sources\n')
                    pin = root / 'internal/catalog/presets.version'
                    pin.parent.mkdir(parents=True)
                    pin.write_bytes(b'v0.2.1\n')
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
                # Only external build tools are simulated; hashing and archives are real.
                boundary = r'''
set -eu
export RELEASE_TAG=v1.2.3
export RELEASE_ARCHITECTURES='amd64 386 armv5 arm64 mipsle mipsbe'
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
'''
                package = release_step('Package source, notices, and build identity')
                result = subprocess.run(['bash', '-ec', boundary + '\n' + package],
                                        cwd=root, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                with tarfile.open(dist / 'keenproxy-notices.tar.gz') as notices:
                    expected_notices = {'LICENSE', 'THIRD_PARTY_NOTICES.md', 'LICENSES'}
                    if with_sources:
                        expected_notices.add('PRESET_SOURCES.md')
                        expected_notices.add('internal/catalog/presets.version')
                        self.assertEqual(notices.extractfile('internal/catalog/presets.version').read(), b'v0.2.1\n')
                    self.assertEqual(set(notices.getnames()), expected_notices)
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


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('jq'),
                     'publication uses GNU sha256sum and jq')
class ReleasePublicationTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.local = self.root / 'dist'
        self.local.mkdir()
        self.remote = self.root / 'remote'
        self.remote.mkdir()
        self.names = {
            f'keenproxy-{variant}linux-{arch}'
            for variant in ('', 'lite-')
            for arch in ('amd64', '386', 'armv5', 'arm64', 'mipsle', 'mipsbe')
        } | {'keenproxy-source.tar.gz', 'keenproxy-notices.tar.gz', 'install.sh',
             'S99keenproxy', 'keenproxy.openwrt', 'BUILD_INFO.txt'}
        self.revision = 'a' * 40
        for name in self.names:
            (self.local / name).write_text(name + '\n')
        (self.local / 'BUILD_INFO.txt').write_text(f'Version: v1.2.3\nCommit: {self.revision}\n')
        (self.local / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256((self.local / name).read_bytes()).hexdigest()}  {name}\n'
            for name in sorted(self.names)))
        self.names.add('SHA256SUMS')

    def publish(self, *, recovery=False, failed_upload='', tag_moved=False, historical=False,
                latest='v1.2.2'):
        boundary = r'''
set -euo pipefail
export RELEASE_ID=42 RELEASE_TAG=v1.2.3 GH_REPO=example/fixture GH_TOKEN=test
endpoint="repos/$GH_REPO/releases/$RELEASE_ID"
gh() {
    case "$2" in
        "$endpoint")
            jq -n --arg sha "$RELEASE_REVISION" --argjson recovery "$RELEASE_RECOVERY" \
                '{tag_name:"v1.2.3",target_commitish:$sha,draft:($recovery|not),prerelease:false}' ;;
        repos/*/commits/refs/tags/v1.2.3)
            if [[ "$TAG_MOVED" == true ]]; then echo different; else echo "$RELEASE_REVISION"; fi ;;
        --paginate)
            if [[ "$4" == "repos/$GH_REPO/releases?per_page=100" ]]; then
                jq -n --arg tag "$TEST_LATEST" '[[{tag_name:$tag, draft:false, prerelease:false}]]'
                return
            fi
            [[ "$4" == "$endpoint/assets?per_page=100" ]]
            (
                shopt -s nullglob
                for path in "$TEST_ROOT"/remote/*; do
                    hash=$(sha256sum "$path")
                    jq -n --arg name "${path##*/}" --arg digest "sha256:${hash%% *}" \
                        '{name:$name,digest:$digest,state:"uploaded"}'
                done
            ) | jq -s '[.]' ;;
        --method)
            [[ "$3" == PATCH && "$4" == "$endpoint" ]]
            [[ "$RELEASE_RECOVERY" == false ]]
            printf '%s\n' "$8" > "$TEST_ROOT/make-latest"
            ls "$TEST_ROOT/remote" > "$TEST_ROOT/published" ;;
        *) return 2 ;;
    esac
}
curl() {
    local arg name=
    for arg in "$@"; do
        case "$arg" in
            https://uploads.github.com/"$endpoint"/assets\?name=*) name=${arg##*=} ;;
        esac
    done
    [[ -n "$name" && ! -e "$TEST_ROOT/remote/$name" ]] || return 2
    if [[ "$name" != "$FAILED_UPLOAD" ]]; then cp "$name" "$TEST_ROOT/remote/$name"; fi
}
source "$PUBLISH_SCRIPT" "$TEST_ROOT/dist"
'''
        env = dict(os.environ, PUBLISH_SCRIPT=str(PUBLISH), TEST_ROOT=str(self.root),
                   RELEASE_REVISION=self.revision, RELEASE_RECOVERY=str(recovery).lower(),
                   RELEASE_NATIVE=str(not historical).lower(),
                   RELEASE_ENTWARE_CONTROLLER=str(not historical).lower(),
                   RELEASE_ARCHITECTURES='arm64 mipsle' if historical else 'amd64 386 armv5 arm64 mipsle mipsbe',
                   FAILED_UPLOAD=failed_upload, TAG_MOVED=str(tag_moved).lower(),
                   TEST_LATEST=latest)
        return subprocess.run(['bash', '-c', boundary], env=env, cwd=self.root,
                              capture_output=True, text=True, timeout=20)

    def test_draft_stays_private_when_upload_incomplete_then_resumes(self):
        result = self.publish(failed_upload='SHA256SUMS')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA256SUMS is missing after upload', result.stderr)
        self.assertFalse((self.root / 'published').exists())

        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set((self.root / 'published').read_text().splitlines()), self.names)
        self.assertEqual((self.root / 'make-latest').read_text().strip(), 'make_latest=true')

    def test_older_draft_does_not_become_latest(self):
        result = self.publish(latest='v1.10.0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'make-latest').read_text().strip(), 'make_latest=false')

    def test_recovery_never_republishes_or_overwrites(self):
        (self.remote / 'install.sh').write_text('different payload\n')
        result = self.publish(recovery=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(set(path.name for path in self.remote.iterdir()), {'install.sh'})
        self.assertEqual((self.remote / 'install.sh').read_text(), 'different payload\n')
        self.assertFalse((self.root / 'published').exists())

        (self.remote / 'install.sh').write_bytes((self.local / 'install.sh').read_bytes())
        result = self.publish(recovery=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(path.name for path in self.remote.iterdir()), self.names)
        self.assertFalse((self.root / 'published').exists())

    def test_repair_accepts_tagged_historical_layout(self):
        historical = {name for name in self.names
                      if not name.endswith(('-386', '-amd64', '-armv5', '-mipsbe', '.openwrt'))}
        historical.remove('S99keenproxy')
        checksums = self.local / 'SHA256SUMS'
        checksums.write_text(''.join(line + '\n' for line in checksums.read_text().splitlines()
                                     if line.split()[1] in historical))

        result = self.publish(recovery=True, historical=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({path.name for path in self.remote.iterdir()}, historical)
        self.assertFalse((self.root / 'published').exists())

    def test_moved_tag_blocks_upload(self):
        result = self.publish(tag_moved=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('tag no longer points', result.stderr)
        self.assertEqual(list(self.remote.iterdir()), [])
