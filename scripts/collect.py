#!/usr/bin/env python3
"""Collect only verified Debian packages from approved Netavark release snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

SUITES = ('trixie', 'forky', 'sid')
ARCHES = ('amd64', 'arm64')
TAG = re.compile(r'netavark-\d{8}\.[1-9]\d*\Z')
CHECKSUM = re.compile(r'([0-9a-f]{64})  ([A-Za-z0-9_.+~:-]+)\Z')
REPO = 'mwyau/netavark-backports'
MAX_ASSET_BYTES = 100 * 1024 * 1024


class CollectionError(Exception):
    pass


def get_bytes(url: str, token: str = '', max_bytes: int = MAX_ASSET_BYTES) -> bytes:
    req = Request(url, headers={
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'xddd-apt-archive-builder',
        **({'Authorization': f'Bearer {token}'} if token else {}),
        'X-GitHub-Api-Version': '2022-11-28',
    })
    with urlopen(req, timeout=90) as response:
        value = response.read(max_bytes + 1)
    if len(value) > max_bytes:
        raise CollectionError(f'Asset exceeds {max_bytes} bytes: {url}')
    return value


def list_releases(repo: str, token: str) -> list[dict]:
    releases = []
    for page in range(1, 101):
        uri = f'https://api.github.com/repos/{repo}/releases?per_page=100&page={page}'
        batch = json.loads(get_bytes(uri, token))
        if not isinstance(batch, list):
            raise CollectionError('GitHub returned an invalid release list')
        releases.extend(batch)
        if len(batch) < 100:
            return releases
    raise CollectionError('Release pagination limit reached; refusing incomplete archive')


def checksums_from_bytes(raw: bytes) -> dict[str, str]:
    result = {}
    for line in raw.decode('utf-8').splitlines():
        match = CHECKSUM.fullmatch(line)
        if not match or match.group(2) in result:
            raise CollectionError(f'Invalid or duplicate SHA256SUMS line: {line[:100]!r}')
        digest, name = match.groups()
        result[name] = digest
    if not result:
        raise CollectionError('Empty SHA256SUMS')
    return result


def debian_names(manifest: dict) -> dict[str, tuple[str, str, str]]:
    result = {}
    for suite in SUITES:
        entry = manifest['debian'][suite]
        source = entry['source']
        revision = entry['revision']
        if not isinstance(source, str) or not re.fullmatch(r'[A-Za-z0-9.+:~\-]+', source):
            raise CollectionError(f'Invalid source version for {suite}')
        if type(revision) is not int or revision < 1:
            raise CollectionError(f'Invalid downstream revision for {suite}')
        version = f'{source}xddd{revision}~{suite}'
        for arch in ARCHES:
            name = f'netavark_{version}_{arch}.deb'
            result[name] = (suite, arch, version)
    return result


def release_assets(release: dict) -> dict[str, dict]:
    assets = {}
    for value in release['assets']:
        name = value['name']
        if name in assets or '/' in name or '\\' in name or Path(name).name != name:
            raise CollectionError(f'Duplicate or unsafe release asset: {name}')
        assets[name] = value
    return assets


def validated_release(release: dict, token: str) -> tuple[dict, dict, dict]:
    assets = release_assets(release)
    for name in ('versions.json', 'SHA256SUMS'):
        if name not in assets:
            raise CollectionError(f'{release["tag_name"]}: missing {name}')

    def download(name: str) -> bytes:
        item = assets[name]
        url = item['browser_download_url']
        parsed = urlparse(url)
        if parsed.scheme != 'https' or parsed.hostname != 'github.com' or not parsed.path.startswith(f'/{REPO}/releases/download/'):
            raise CollectionError(f'Unexpected asset download URL for {name}')
        return get_bytes(url, token)

    checksums = checksums_from_bytes(download('SHA256SUMS'))
    manifest_bytes = download('versions.json')
    if hashlib.sha256(manifest_bytes).hexdigest() != checksums.get('versions.json'):
        raise CollectionError('versions.json checksum mismatch')
    manifest = json.loads(manifest_bytes)
    expected = debian_names(manifest)
    if set(expected) - set(assets) or set(expected) - set(checksums):
        raise CollectionError(f'{release["tag_name"]}: incomplete Debian asset snapshot')
    # A complete snapshot may contain Ubuntu, RPM and source assets; only Debian binaries are downloaded.
    if set(checksums) != (set(assets) - {'SHA256SUMS'}):
        raise CollectionError(f'{release["tag_name"]}: asset names differ from checksum manifest')
    return expected, assets, checksums


def load_lock(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text())
    if data.get('schema') != 1 or not isinstance(data.get('packages'), dict):
        raise CollectionError('Invalid archive lock file')
    return data['packages']


def collect(releases: list[dict], destination: Path, lock: dict[str, str], token: str) -> dict:
    approved = sorted((r for r in releases if TAG.fullmatch(r.get('tag_name', ''))
                       and not r.get('draft') and not r.get('prerelease')),
                      key=lambda r: (int(r['tag_name'][9:17]), int(r['tag_name'].split('.')[-1])))
    if not approved:
        raise CollectionError('No approved published netavark-* Releases; do not use CI drafts')
    destination.mkdir(parents=True, exist_ok=True)
    observed: dict[str, str] = {}
    provenance: dict[str, list[str]] = {}
    for release in approved:
        names, assets, sums = validated_release(release, token)
        for name, (suite, arch, version) in sorted(names.items()):
            digest = sums[name]
            if name in observed:
                if observed[name] != digest:
                    raise CollectionError(f'Conflicting bytes for historical package {name}')
                provenance[name].append(release['tag_name'])
                continue
            if name in lock and lock[name] != digest:
                raise CollectionError(f'Historical artifact changed since archive lock: {name}')
            item = assets[name]
            # The release data is reviewed independently; never trust filenames without hash verification.
            url = item['browser_download_url']
            parsed = urlparse(url)
            if parsed.scheme != 'https' or parsed.hostname != 'github.com' or not parsed.path.startswith(f'/{REPO}/releases/download/'):
                raise CollectionError(f'Unexpected package URL: {name}')
            contents = get_bytes(url, token)
            if hashlib.sha256(contents).hexdigest() != digest:
                raise CollectionError(f'Package SHA256 mismatch: {name}')
            folder = destination / suite
            folder.mkdir(exist_ok=True)
            (folder / name).write_bytes(contents)
            observed[name] = digest
            provenance[name] = [release['tag_name']]
    missing = set(lock) - set(observed)
    if missing:
        raise CollectionError(f'Previously locked packages disappeared: {sorted(missing)}')
    return {'schema': 1, 'packages': dict(sorted(observed.items())),
            'releases': [r['tag_name'] for r in approved], 'provenance': provenance}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default=REPO, choices=[REPO])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--lock', type=Path, default=Path('archive-lock.json'))
    parser.add_argument('--candidate-lock', type=Path, required=True)
    args = parser.parse_args()
    import os
    token = os.getenv('GH_TOKEN', '')
    try:
        candidate = collect(list_releases(args.repo, token), args.output, load_lock(args.lock), token)
        args.candidate_lock.parent.mkdir(parents=True, exist_ok=True)
        args.candidate_lock.write_text(json.dumps({'schema': 1, 'packages': candidate['packages']}, indent=2) + '\n')
        print(f'Collected {len(candidate["packages"])} distinct Debian packages from {len(candidate["releases"])} published releases')
    except (CollectionError, ValueError, KeyError, OSError) as exc:
        sys.exit(f'ERROR: {exc}')


if __name__ == '__main__':
    main()
