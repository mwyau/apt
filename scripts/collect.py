#!/usr/bin/env python3
"""Collect only verified Debian packages from approved Netavark release snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

SUITES = ('trixie', 'forky', 'sid')
ARCHES = ('amd64', 'arm64')
TAG = re.compile(r'netavark-\d{8}\.[1-9]\d*\Z')
CHECKSUM = re.compile(r'([0-9a-f]{64})  ([A-Za-z0-9_.+~:-]+)\Z')
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


def validated_release(release: dict, token: str, repo: str) -> tuple[dict, dict, dict]:
    assets = release_assets(release)
    for name in ('versions.json', 'SHA256SUMS'):
        if name not in assets:
            raise CollectionError(f'{release["tag_name"]}: missing {name}')

    def download(name: str) -> bytes:
        item = assets[name]
        url = item['browser_download_url']
        parsed = urlparse(url)
        if parsed.scheme != 'https' or parsed.hostname != 'github.com' or not parsed.path.startswith(f'/{repo}/releases/download/'):
            raise CollectionError(f'Unexpected asset download URL for {name}')
        return get_bytes(url)

    checksums = checksums_from_bytes(download('SHA256SUMS'))
    manifest_bytes = download('versions.json')
    if hashlib.sha256(manifest_bytes).hexdigest() != checksums.get('versions.json'):
        raise CollectionError('versions.json checksum mismatch')
    manifest = json.loads(manifest_bytes)
    expected = debian_names(manifest)

    # GitHub normalizes certain characters in uploaded asset filenames.
    # The original checksum manifest records canonical Debian names (e.g. ~trixie),
    # while the GitHub asset may be named .trixie. Never weaken checksum validation.
    checked_assets = {}
    for canonical, checksum in checksums.items():
        candidates = [name for name in (canonical, canonical.replace('~', '.')) if name in assets]
        if len(set(candidates)) != 1:
            raise CollectionError(f'{release["tag_name"]}: missing or ambiguous asset for {canonical}')
        actual = candidates[0]
        if actual in checked_assets:
            raise CollectionError(f'{release["tag_name"]}: duplicate mapping for asset {actual}')
        asset_digest = assets[actual].get('digest')
        if asset_digest and asset_digest != 'sha256:' + checksum:
            raise CollectionError(f'{release["tag_name"]}: GitHub asset digest conflict for {actual}')
        checked_assets[actual] = canonical
    if set(checked_assets) != (set(assets) - {'SHA256SUMS'}):
        raise CollectionError(f'{release["tag_name"]}: asset names differ from checksum manifest')
    if set(expected) - set(checksums):
        raise CollectionError(f'{release["tag_name"]}: missing canonical Debian checksums')

    # Normalize only the selected Debian asset references, retaining their
    # checksum-manifest names as keys and the actual GitHub URLs as values.
    normalized = {canonical: assets[actual] for actual, canonical in checked_assets.items()}
    if set(expected) - set(normalized):
        raise CollectionError(f'{release["tag_name"]}: incomplete Debian asset snapshot')
    return expected, normalized, checksums


def verify_deb_control(path: Path, suite: str, arch: str, version: str) -> None:
    """Check the signed asset's actual Debian control fields, not just its name."""
    try:
        values = subprocess.check_output(
            ['dpkg-deb', '--field', str(path), 'Package', 'Version', 'Architecture'],
            text=True, stderr=subprocess.PIPE,
        ).splitlines()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CollectionError(f'Invalid Debian package: {path.name}') from exc
    expected = [f'Package: netavark', f'Version: {version}', f'Architecture: {arch}']
    if values != expected:
        raise CollectionError(
            f'Control metadata mismatch for {suite}/{path.name}: '
            f'expected (netavark, {version}, {arch}), found {values!r}')


def load_lock(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text())
    if data.get('schema') != 1 or not isinstance(data.get('packages'), dict):
        raise CollectionError('Invalid archive lock file')
    locked = data['packages']
    for name, sha in locked.items():
        if not isinstance(name, str) or not re.fullmatch(
                r'netavark_[0-9][A-Za-z0-9.+:~-]*~(?:trixie|forky|sid)_(?:amd64|arm64)[.]deb',
                name):
            raise CollectionError(f'Invalid archive lock package name: {name!r}')
        if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha):
            raise CollectionError(f'Invalid archive lock SHA-256 for {name}')
    return locked


def collect(releases: list[dict], destination: Path, lock: dict[str, str], token: str, repo: str) -> dict:
    approved = sorted((r for r in releases if TAG.fullmatch(r.get('tag_name', ''))
                       and not r.get('draft') and not r.get('prerelease')),
                      key=lambda r: (int(r['tag_name'][9:17]), int(r['tag_name'].split('.')[-1])))
    if not approved:
        raise CollectionError('No approved published netavark-* Releases; do not use CI drafts')
    destination.mkdir(parents=True, exist_ok=True)
    observed: dict[str, str] = {}
    provenance: dict[str, list[str]] = {}
    upload_dates: dict[str, str | None] = {}
    for release in approved:
        names, assets, sums = validated_release(release, token, repo)
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
            if parsed.scheme != 'https' or parsed.hostname != 'github.com' or not parsed.path.startswith(f'/{repo}/releases/download/'):
                raise CollectionError(f'Unexpected package URL: {name}')
            contents = get_bytes(url)
            if hashlib.sha256(contents).hexdigest() != digest:
                raise CollectionError(f'Package SHA256 mismatch: {name}')
            folder = destination / suite
            folder.mkdir(exist_ok=True)
            destination_file = folder / name
            destination_file.write_bytes(contents)
            verify_deb_control(destination_file, suite, arch, version)
            observed[name] = digest
            provenance[name] = [release['tag_name']]
            upload_dates[name] = item.get('created_at')
    missing = set(lock) - set(observed)
    if missing:
        raise CollectionError(f'Previously locked packages disappeared: {sorted(missing)}')
    return {'schema': 1, 'repository': repo, 'packages': dict(sorted(observed.items())),
            'releases': [r['tag_name'] for r in approved], 'provenance': provenance,
            'uploaded_at': upload_dates,
            'release_metadata': [
                {'tag': r['tag_name'], 'published_at': r.get('published_at'),
                 'source_commit': r.get('target_commitish')}
                for r in approved]}


def load_sources(path: Path) -> list[str]:
    """Only published Netavark-format releases are currently supported."""
    data = json.loads(path.read_text())
    if data.get('schema') != 1 or not isinstance(data.get('sources'), list):
        raise CollectionError('Invalid archive source configuration')
    sources = data['sources']
    if not sources:
        raise CollectionError('At least one source is required')
    repos: list[str] = []
    for source in sources:
        if not isinstance(source, dict) or source.get('format') != 'netavark-releases-v1':
            raise CollectionError('Unsupported source format (expected netavark-releases-v1)')
        repository = source.get('repository')
        if not isinstance(repository, str) or not re.fullmatch(
                r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
            raise CollectionError(f'Invalid GitHub source repository: {repository!r}')
        if repository in repos:
            raise CollectionError(f'Duplicate GitHub source: {repository}')
        repos.append(repository)
    return repos


def collect_sources(repositories: list[str], destination: Path,
                    lock: dict[str, str], token: str) -> dict:
    """Combine compatible repositories while rejecting overlapping package identities."""
    destination.mkdir(parents=True, exist_ok=True)
    all_packages: dict[str, str] = {}
    all_releases: list[dict] = []
    all_provenance: dict[str, list[str]] = {}
    upload_dates: dict[str, str | None] = {}
    with tempfile.TemporaryDirectory() as work:
        for index, repo in enumerate(repositories):
            stage = Path(work) / str(index)
            candidate = collect(list_releases(repo, token), stage, {}, token, repo)
            for name, sha in candidate['packages'].items():
                if name in all_packages:
                    raise CollectionError(f'Package filename collision across sources: {name}')
                all_packages[name] = sha
                for suite in SUITES:
                    item = stage / suite / name
                    if item.is_file():
                        target = destination / suite / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(item, target)
                        break
                else:
                    raise CollectionError(f'Missing collected package: {name}')
                all_provenance[name] = [f"{repo}@{tag}"
                                        for tag in candidate['provenance'][name]]
                upload_dates[name] = candidate['uploaded_at'][name]
            for release in candidate['release_metadata']:
                all_releases.append({'repository': repo, **release})
    for name, expected_sha in lock.items():
        if name not in all_packages:
            raise CollectionError(f'Previously locked package disappeared: {name}')
        if all_packages[name] != expected_sha:
            raise CollectionError(f'Historical artifact changed since archive lock: {name}')
    return {'schema': 1, 'packages': dict(sorted(all_packages.items())),
            'release_metadata': all_releases, 'provenance': all_provenance,
            'uploaded_at': upload_dates}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', type=Path, default=Path('archive/sources.json'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--lock', type=Path, default=Path('archive/package-lock.json'))
    parser.add_argument('--candidate-lock', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--require-locked', action='store_true',
                        help='Fail if any unreviewed new package is discovered')
    args = parser.parse_args()
    import os
    token = os.getenv('GH_TOKEN', '')
    try:
        repositories = load_sources(args.sources)
        lock = load_lock(args.lock)
        candidate = collect_sources(repositories, args.output, lock, token)
        if args.require_locked and candidate['packages'] != lock:
            additions = sorted(set(candidate['packages']) - set(lock))
            raise CollectionError(
                f'Unreviewed new packages: {additions}. Review and merge a package-lock PR first')
        args.candidate_lock.parent.mkdir(parents=True, exist_ok=True)
        args.candidate_lock.write_text(
            json.dumps({'schema': 1, 'packages': candidate['packages']}, indent=2) + '\n')
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest = {
            'schema': 1,
            'source_repositories': repositories,
            'releases': candidate['release_metadata'],
            'packages': {
                name: {
                    'sha256': sha,
                    'release_ids': candidate['provenance'][name],
                    'github_asset_uploaded_at': candidate['uploaded_at'][name],
                }
                for name, sha in candidate['packages'].items()
            },
        }
        args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        print(f'Collected {len(candidate["packages"])} locked Debian packages '
              f'from {len(candidate["release_metadata"])} source releases')
    except (CollectionError, ValueError, KeyError, OSError, TypeError) as exc:
        sys.exit(f'ERROR: {exc}')


if __name__ == '__main__':
    main()
