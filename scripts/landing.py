#!/usr/bin/env python3
"""Render a small Debian-style landing page from the generated APT indexes.

The CI archive is test-signed and unpublished. Installation commands are
explicitly marked as templates for a separately approved production release.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from functools import cmp_to_key
import gzip
from html import escape
import json
from pathlib import Path
from string import Template
import subprocess

SUITE_ORDER = ('trixie', 'forky', 'sid')
ARCH_ORDER = ('amd64', 'arm64')
REPOSITORY_URL = 'https://apt.xddd.org'
TEMPLATE_PATH = Path(__file__).resolve().parents[1] / 'templates' / 'index.html'


def version_compare(left: str, right: str) -> int:
    """Use Debian's version algorithm, not lexicographic comparisons."""
    if subprocess.run(['dpkg', '--compare-versions', left, 'lt', right],
                      check=False).returncode == 0:
        return -1
    if subprocess.run(['dpkg', '--compare-versions', left, 'gt', right],
                      check=False).returncode == 0:
        return 1
    return 0


def packages_from_indexes(site: Path) -> tuple[dict, dict]:
    result: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set))
    descriptions: dict[tuple[str, str], str] = {}
    for suite in SUITE_ORDER:
        for arch in ARCH_ORDER:
            path = site / 'dists' / suite / 'main' / f'binary-{arch}' / 'Packages.gz'
            with gzip.open(path, 'rt', encoding='utf-8') as archive:
                for stanza in archive.read().split('\n\n'):
                    entries = dict(line.split(': ', 1)
                                   for line in stanza.splitlines()
                                   if ': ' in line and not line.startswith(' '))
                    if not entries:
                        continue
                    if entries.get('Architecture') != arch:
                        raise ValueError(f'Wrong package architecture in {path}')
                    package = entries['Package']
                    version = entries['Version']
                    result[(suite, package)][version].add(arch)
                    description = entries.get('Description', '').strip()
                    if description:
                        descriptions.setdefault((suite, package), description)
    if not result:
        raise ValueError('No packages in APT indexes')
    return result, descriptions


def package_rows(indexes: dict, descriptions: dict) -> tuple[str, str, str, str]:
    lines: list[str] = []
    first_package: str | None = None
    first_version: str | None = None
    first_suite: str | None = None
    for suite, package in sorted(indexes,
                                 key=lambda pair: (SUITE_ORDER.index(pair[0]), pair[1])):
        versions = sorted(indexes[(suite, package)], key=cmp_to_key(version_compare),
                          reverse=True)
        newest = versions[0]
        if first_package is None:
            first_package, first_version, first_suite = package, newest, suite
        architectures = ', '.join(
            arch for arch in ARCH_ORDER if arch in indexes[(suite, package)][newest])
        additional = ''
        if len(versions) > 1:
            historical = ', '.join(
                f'<code>{escape(version)}</code>' for version in versions[1:])
            additional = (
                f'<details><summary>{len(versions) - 1} older version(s)</summary>'
                f'<p>{historical}</p></details>')
        description = descriptions.get((suite, package), '')
        summary = (f'<span class="small summary">{escape(description)}</span>'
                   if description else '')
        lines.append(
            '<tr>'
            f'<th scope="row">{escape(package)}{summary}</th>'
            f'<td><code>{escape(suite)}</code></td>'
            f'<td><code>{escape(newest)}</code>{additional}</td>'
            f'<td>{escape(architectures)}</td>'
            '</tr>')
    assert first_package and first_version and first_suite
    return '\n'.join(lines), first_package, first_version, first_suite


def render(site: Path) -> str:
    indexes, descriptions = packages_from_indexes(site)
    rows, package, version, suite = package_rows(indexes, descriptions)
    provenance = json.loads((site / 'archive-provenance.json').read_text())
    repos = provenance.get('source_repositories', [])
    if not isinstance(repos, list) or not repos:
        raise ValueError('Missing archive source repositories')
    sources = ', '.join(
        f'<a href="https://github.com/{escape(repo, quote=True)}">'
        f'{escape(repo)}</a>' for repo in sorted(repos))
    # Code examples are intentionally NOT runnable against the ephemeral CI
    # test key; the published site needs a stable independently reviewed key.
    key_command = (
        'sudo install -d -m 0755 /etc/apt/keyrings\n'
        f'curl -fsSL {REPOSITORY_URL}/xddd-archive-keyring.gpg '
        '| sudo tee /etc/apt/keyrings/xddd-archive-keyring.gpg >/dev/null\n'
        'sudo chmod 0644 /etc/apt/keyrings/xddd-archive-keyring.gpg')
    sources_command = (
        "sudo tee /etc/apt/sources.list.d/xddd.sources >/dev/null <<'EOF'\n"
        'Types: deb\n'
        f'URIs: {REPOSITORY_URL}/\n'
        f'Suites: {suite}\n'
        'Components: main\n'
        'Architectures: amd64 arm64\n'
        'Signed-By: /etc/apt/keyrings/xddd-archive-keyring.gpg\n'
        'EOF')
    install_command = (
        'sudo apt update\n'
        f'apt-cache policy {package}\n'
        f'sudo apt install {package}={version}')
    template = Template(TEMPLATE_PATH.read_text(encoding='utf-8'))
    return template.substitute(
        ROWS=rows,
        SUITE=escape(suite),
        KEY_COMMAND=escape(key_command),
        SOURCES_COMMAND=escape(sources_command),
        INSTALL_COMMAND=escape(install_command),
        SOURCES=sources,
    )



def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', type=Path, required=True)
    args = parser.parse_args()
    (args.site / 'index.html').write_text(render(args.site), encoding='utf-8')


if __name__ == '__main__':
    main()
