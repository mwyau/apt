#!/usr/bin/env python3
"""Validate signed APT metadata, retained package versions, and file references."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import subprocess
import sys
from pathlib import Path

SUITES = ('trixie', 'forky', 'sid')
ARCHES = ('amd64', 'arm64')


def fields(text: str) -> dict[str, str]:
    return dict(line.split(': ', 1) for line in text.splitlines() if ': ' in line and not line.startswith(' '))


def verify(site: Path, mode: str) -> None:
    public = site / 'xddd-archive-keyring.gpg'
    if not public.is_file() or not public.stat().st_size:
        raise ValueError('Missing public keyring')
    for suite in SUITES:
        dist = site / 'dists' / suite
        for signature, args in [('InRelease', [str(dist / 'InRelease')]),
                                ('Release.gpg', [str(dist / 'Release.gpg'), str(dist / 'Release')])]:
            subprocess.run(['gpgv', '--keyring', str(public), *args], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        release = fields((dist / 'Release').read_text())
        if release.get('NotAutomatic') != 'yes' or release.get('ButAutomaticUpgrades') != 'yes':
            raise ValueError(f'{suite}: missing safe APT priority flags')
        if release.get('Acquire-By-Hash') != 'yes':
            raise ValueError(f'{suite}: missing by-hash marker')
        for arch in ARCHES:
            path = dist / 'main' / f'binary-{arch}' / 'Packages.gz'
            with gzip.open(path, 'rt') as file:
                stanzas = [fields(item) for item in file.read().split('\n\n') if item.strip()]
            if not stanzas:
                raise ValueError(f'No indexed packages in {suite}/{arch}')
            versions = set()
            for entry in stanzas:
                if entry.get('Architecture') != arch:
                    raise ValueError(f'Wrong package architecture for {suite}/{arch}')
                name = entry['Filename']
                if name.startswith('/') or '..' in Path(name).parts:
                    raise ValueError(f'Unsafe package filename {name}')
                package = site / name
                if not package.is_file():
                    raise ValueError(f'Missing indexed package {name}')
                if hashlib.sha256(package.read_bytes()).hexdigest() != entry['SHA256']:
                    raise ValueError(f'Package checksum mismatch for {name}')
                if package.stat().st_size != int(entry['Size']):
                    raise ValueError(f'Package size mismatch for {name}')
                versions.add((entry['Package'], entry['Version']))
            if mode == 'fixture':
                selected = [ver for name, ver in versions if name == 'xddd-apt-test-fixture']
                if len(selected) != 2:
                    raise ValueError(f'Missing historical fixture versions for {suite}/{arch}')
            print(f'PASS: {suite}/{arch}: {len(stanzas)} indexed packages')
    # APT itself must accept local file source and test key in an isolated index directory.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        lists = root / 'lists'
        (lists / 'partial').mkdir(parents=True)
        sources = root / 'sources.list'
        sources.write_text(f'deb [signed-by={public.resolve()}] file:{site.resolve()} trixie main\n')
        cmd = ['apt-get', '-o', f'Dir::Etc::sourcelist={sources}',
               '-o', 'Dir::Etc::sourceparts=-', '-o', f'Dir::State::lists={lists}',
               '-o', 'Dir::Etc::trusted=/dev/null', '-o', 'Dir::Etc::trustedparts=-',
               '-o', 'Debug::NoLocking=1', '-o', 'APT::Get::List-Cleanup=0',
               'update']
        subprocess.run(cmd, check=True)
        print('PASS: apt-get update accepts signed Trixie repository')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--site', type=Path, required=True)
    p.add_argument('--mode', choices=('fixture', 'releases'), required=True)
    a = p.parse_args()
    try:
        verify(a.site, a.mode)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as e:
        sys.exit(f'FAIL: {e}')
