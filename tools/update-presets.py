#!/usr/bin/env python3
"""Import a newer stable catalog into the checkout for PR review."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

REPO = 'ordo-systems/keenproxy-presets'
CATALOG = Path('internal/catalog')
PIN = CATALOG / 'presets.version'
LICENSES = Path('LICENSES/presets')
ARCHIVE = 'keenproxy-preset-notices.tar.gz'
PAYLOAD = ('presets.json', 'PRESET_SOURCES.md', 'sources.lock.json', ARCHIVE)


def gh(*args):
    return subprocess.check_output(['gh', 'release', *args, '--repo', REPO], text=True)


def version(tag):
    match = re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag)
    if not match:
        raise ValueError(f'not a stable catalog tag: {tag!r}')
    return tuple(map(int, match.groups()))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_release(directory, assets):
    files = {name: (directory / name).read_bytes() for name in (*PAYLOAD, 'SHA256SUMS')}
    for name, data in files.items():
        if assets.get(name) != 'sha256:' + digest(data):
            raise ValueError(f'published digest mismatch: {name}')
    manifest = {}
    for line in files['SHA256SUMS'].decode().splitlines():
        checksum, name = line.split()
        if name in manifest:
            raise ValueError(f'duplicate SHA256SUMS entry: {name}')
        manifest[name] = checksum
    if manifest != {name: digest(files[name]) for name in PAYLOAD}:
        raise ValueError('SHA256SUMS does not match catalog release payload')
    lock = json.loads(files['sources.lock.json'])
    if lock['output_sha256'] != manifest['presets.json']:
        raise ValueError('source lock does not match catalog')

    presets = json.loads(files['presets.json'])
    ids = [preset['id'] for preset in presets]
    if not ids or any(not isinstance(id_, str) or not id_ for id_ in ids) or len(set(ids)) != len(ids):
        raise ValueError('catalog must contain presets with unique nonempty IDs')

    vendored = {CATALOG / 'presets.json': files['presets.json'],
                Path('PRESET_SOURCES.md'): files['PRESET_SOURCES.md']}
    seen = set()
    with tarfile.open(directory / ARCHIVE, 'r:gz') as archive:
        for member in archive:
            if not member.name.startswith('LICENSES/'):
                continue
            name = member.name.removeprefix('LICENSES/')
            if not member.isfile() or not re.fullmatch(r'[a-zA-Z0-9_-]+\.txt', name) or name in seen:
                raise ValueError(f'invalid license member: {member.name!r}')
            seen.add(name)
            with archive.extractfile(member) as stream:
                vendored[LICENSES / name] = stream.read()
    expected = {source['license_file'] for source in lock['sources'].values()}
    if not seen or expected != {f'LICENSES/{name}' for name in seen}:
        raise ValueError('notices archive license files do not match source lock')
    return vendored


def main():
    pinned = PIN.read_text().strip()
    release = json.loads(gh('view', '--json', 'tagName,isDraft,isPrerelease,assets'))
    tag = release['tagName']
    if release['isDraft'] or release['isPrerelease']:
        raise ValueError('latest catalog release is not stable')
    if version(tag) <= version(pinned):
        print(f'Catalog already current: {pinned} (upstream: {tag})')
        return

    assets = {asset['name']: asset['digest'] for asset in release['assets']}
    with tempfile.TemporaryDirectory() as tmp:
        gh('download', tag, '--dir', tmp, *(item for name in (*PAYLOAD, 'SHA256SUMS')
                                           for item in ('--pattern', name)))
        vendored = verify_release(Path(tmp), assets)

    LICENSES.mkdir(parents=True, exist_ok=True)
    for path in LICENSES.glob('*.txt'):
        if path not in vendored:
            path.unlink()
    for path, data in vendored.items():
        path.write_bytes(data)
    (CATALOG / 'presets.sha256').write_text(''.join(
        f'{digest(data)}  {path.as_posix()}\n' for path, data in sorted(vendored.items())))
    PIN.write_text(f'{tag}\n')
    if output := os.environ.get('GITHUB_OUTPUT'):
        with Path(output).open('a') as stream:
            stream.write(f'version={tag}\n')
    print(f'Imported catalog {tag}')


if __name__ == '__main__':
    main()
