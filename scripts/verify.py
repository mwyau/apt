#!/usr/bin/env python3
"""Independently verify a complete, signed APT archive built from approved packages."""
from __future__ import annotations

import argparse
from collections import defaultdict
from functools import partial
import gzip
import hashlib
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread

SUITES = ('trixie', 'forky', 'sid')
ARCHES = ('amd64', 'arm64')


def fields(text: str) -> dict[str, str]:
    return dict(line.split(': ', 1) for line in text.splitlines()
                if ': ' in line and not line.startswith(' '))


def control(path: Path) -> tuple[str, str, str]:
    lines = subprocess.check_output(
        ['dpkg-deb', '--field', str(path), 'Package', 'Version', 'Architecture'],
        text=True, stderr=subprocess.PIPE,
    ).splitlines()
    expected_keys = ('Package', 'Version', 'Architecture')
    if len(lines) != 3:
        raise ValueError(f'Invalid Debian package control fields: {path.name}')
    pairs = [line.partition(': ') for line in lines]
    if any(sep != ': ' or key != expected for (key, sep, _value), expected
           in zip(pairs, expected_keys)):
        raise ValueError(f'Unexpected Debian control fields: {path.name}')
    return tuple(value for _key, _sep, value in pairs)


def expected_packages(packages: Path) -> dict[tuple[str, str], set[tuple[str, str, str, str]]]:
    """The input binaries are the complete expected set, not just a minimum."""
    expected = defaultdict(set)
    for suite in SUITES:
        directory = packages / suite
        binaries = sorted(directory.glob('*.deb'))
        if not binaries:
            raise ValueError(f'No approved Debian packages for {suite}')
        for path in binaries:
            package, version, arch = control(path)
            if package != 'netavark' or arch not in ARCHES or not version.endswith(f'~{suite}'):
                raise ValueError(f'Unexpected control fields in {suite}: {package} {version} {arch}')
            if path.name != f'{package}_{version}_{arch}.deb':
                raise ValueError(f'Noncanonical approved Debian filename: {path.name}')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            item = (package, version, arch, digest)
            if item in expected[(suite, arch)]:
                raise ValueError(f'Duplicate approved Debian package: {path}')
            expected[(suite, arch)].add(item)
        for arch in ARCHES:
            if not expected[(suite, arch)]:
                raise ValueError(f'Missing {arch} binaries for {suite}')
    return expected


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass


def validate_apt_http(site: Path, public: Path, expected: dict) -> None:
    """Test the HTTP deployment shape, APT signatures and advertised versions."""
    server = HTTPServer(
        ('localhost', 0), partial(QuietHandler, directory=str(site.resolve())))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f'http://localhost:{server.server_address[1]}'
        for suite in SUITES:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                lists = root / 'lists'
                (lists / 'partial').mkdir(parents=True)
                sources = root / 'sources.list'
                sources.write_text(f'deb [signed-by={public.resolve()}] {origin} {suite} main\n')
                common = [
                    '-o', f'Dir::Etc::sourcelist={sources}',
                    '-o', 'Dir::Etc::sourceparts=-',
                    '-o', f'Dir::State::lists={lists}',
                    '-o', 'Dir::Etc::trusted=/dev/null',
                    '-o', 'Dir::Etc::trustedparts=-',
                    '-o', 'Debug::NoLocking=1',
                    '-o', 'Acquire::http::Proxy=DIRECT',
                    '-o', 'Acquire::ForceIPv4=true',
                ]
                subprocess.run(['apt-get', *common, '-o', 'APT::Update::Error-Mode=any',
                                'update'], check=True)
                lines = subprocess.check_output(
                    ['apt-cache', *common, 'madison', 'netavark'], text=True)
                advertised = {line.split('|')[1].strip()
                              for line in lines.splitlines() if len(line.split('|')) >= 3}
                required = {version for name, version, _arch, _sha
                            in expected[(suite, 'amd64')] if name == 'netavark'}
                if advertised != required:
                    raise ValueError(f'{suite}: APT versions {advertised} != {required}')
                print(f'PASS: HTTP APT update and {len(required)} version(s) for {suite}')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def verify(site: Path, packages: Path) -> None:
    public = site / 'xddd-archive-keyring.gpg'
    if not public.is_file() or not public.stat().st_size:
        raise ValueError('Missing public keyring')
    expected = expected_packages(packages)
    for suite in SUITES:
        dist = site / 'dists' / suite
        for args in ([str(dist / 'InRelease')],
                     [str(dist / 'Release.gpg'), str(dist / 'Release')]):
            subprocess.run(['gpgv', '--keyring', str(public), *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        release = fields((dist / 'Release').read_text())
        if release.get('NotAutomatic') != 'yes' or release.get('ButAutomaticUpgrades') != 'yes':
            raise ValueError(f'{suite}: missing safe APT priority flags')
        if release.get('Acquire-By-Hash') != 'yes':
            raise ValueError(f'{suite}: missing by-hash marker')
        if release.get('Origin') != 'XDDD':
            raise ValueError(f'{suite}: wrong archive Origin')
        if not set(ARCHES).issubset(release.get('Architectures', '').split()):
            raise ValueError(f'{suite}: incomplete architecture list')
        for arch in ARCHES:
            path = dist / 'main' / f'binary-{arch}' / 'Packages.gz'
            with gzip.open(path, 'rt') as stream:
                entries = [fields(item) for item in stream.read().split('\n\n') if item.strip()]
            observed = set()
            for entry in entries:
                if entry.get('Architecture') != arch:
                    raise ValueError(f'Unexpected architecture in {suite}/{arch} index')
                name = entry['Filename']
                if name.startswith('/') or '..' in Path(name).parts:
                    raise ValueError(f'Unsafe indexed package filename: {name}')
                package_path = (site / name).resolve()
                if not package_path.is_relative_to(site.resolve()) or not package_path.is_file():
                    raise ValueError(f'Missing or escaping indexed package: {name}')
                digest = hashlib.sha256(package_path.read_bytes()).hexdigest()
                if digest != entry['SHA256'] or package_path.stat().st_size != int(entry['Size']):
                    raise ValueError(f'Indexed package content mismatch: {name}')
                identity = (entry['Package'], entry['Version'], entry['Architecture'], digest)
                if identity in observed:
                    raise ValueError(f'Duplicate package in {suite}/{arch}: {identity}')
                observed.add(identity)
            if observed != expected[(suite, arch)]:
                missing = expected[(suite, arch)] - observed
                extra = observed - expected[(suite, arch)]
                raise ValueError(f'{suite}/{arch}: missing indexed versions={missing}; '
                                 f'unexpected indexed versions={extra}')
            print(f'PASS: {suite}/{arch}: all {len(observed)} approved versions indexed')
    provenance_path = site / 'archive-provenance.json'
    provenance = json.loads(provenance_path.read_text())
    if provenance.get('schema') != 1 or provenance.get('source_repository') != 'mwyau/netavark-backports':
        raise ValueError('Invalid source provenance')
    if not provenance.get('releases'):
        raise ValueError('Missing approved source release records')
    expected_hashes = {}
    for identities in expected.values():
        for package, version, arch, sha in identities:
            name = f'{package}_{version}_{arch}.deb'
            if name in expected_hashes:
                raise ValueError(f'Duplicate package identity across suites: {name}')
            expected_hashes[name] = sha
    records = provenance.get('packages')
    if not isinstance(records, dict) or set(records) != set(expected_hashes):
        raise ValueError('Source provenance does not cover every indexed package')
    approved_tags = {item['tag'] for item in provenance['releases']}
    for name, sha in expected_hashes.items():
        entry = records[name]
        if entry.get('sha256') != sha or not entry.get('release_tags'):
            raise ValueError(f'Incorrect provenance checksum or release history: {name}')
        if set(entry['release_tags']) - approved_tags:
            raise ValueError(f'Unrecognized source release in provenance: {name}')
    print(f'PASS: provenance covers {len(records)} verified Debian binaries')
    validate_apt_http(site, public, expected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', type=Path, required=True)
    parser.add_argument('--packages', type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.site, args.packages)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        sys.exit(f'FAIL: {exc}')
