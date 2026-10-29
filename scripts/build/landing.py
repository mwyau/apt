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
import subprocess

SUITE_ORDER = ('trixie', 'forky', 'sid')
ARCH_ORDER = ('amd64', 'arm64')
REPOSITORY_URL = 'https://apt.xddd.org'


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
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>XDDD APT repository — Debian packages</title>
<style>
:root {{ color-scheme: light; font-family: system-ui, -apple-system, sans-serif;
         line-height: 1.55; color: #252329; background: #fff; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0 auto; max-width: 860px; padding: 2rem 1.3rem 3rem; }}
header {{ border-bottom: 3px solid #d70a53; padding-bottom: 1rem; }}
h1 {{ font-size: 1.9rem; letter-spacing: -.03em; margin: .2rem 0; }}
h2 {{ font-size: 1.25rem; margin-top: 2rem; }}
p {{ max-width: 75ch; }}
a {{ color: #ac0641; text-underline-offset: 2px; }}
a:hover {{ color: #72002a; }}
.notice {{ background: #fff4f7; border-left: 4px solid #d70a53;
           padding: .75rem 1rem; margin: 1.4rem 0; }}
.notice p {{ margin: .2rem 0; }}
table {{ border-collapse: collapse; width: 100%; font-size: .95rem; }}
th, td {{ text-align: left; padding: .7rem .5rem; vertical-align: top;
          border-bottom: 1px solid #e4e1e3; }}
thead {{ background: #f6f5f5; }}
th {{ font-weight: 650; }}
.summary {{ display: block; font-weight: 400; margin-top: .15rem; }}
code, pre {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .88em; }}
code {{ overflow-wrap: anywhere; }}
pre {{ padding: 1rem; border: 1px solid #e4e1e3; background: #f8f8f8;
       border-radius: 3px; overflow-x: auto; white-space: pre; line-height: 1.5; }}
pre code {{ overflow-wrap: normal; }}
details summary {{ cursor: pointer; color: #51444b; font-size: .85rem; }}
details p {{ margin: .25rem 0 0; }}
.small, footer {{ font-size: .88rem; color: #5d565c; }}
footer {{ border-top: 1px solid #e4e1e3; margin-top: 2.2rem; padding-top: .8rem; }}
</style>
</head>
<body>
<header>
<h1>XDDD APT repository</h1>
<p>Unofficial Debian packages, distributed as a signed APT archive.</p>
</header>
<div class="notice" role="note">
<strong>CI preview — not a public repository.</strong>
<p>This build is signed with a short-lived test key. Do not add it to a
system or install packages from it. The commands below are for a future,
separately approved production release.</p>
</div>
<section aria-labelledby="packages">
<h2 id="packages">Available packages</h2>
<table>
<thead><tr><th scope="col">Package</th><th scope="col">Debian suite</th>
<th scope="col">Latest version</th><th scope="col">Architectures</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
<p class="small">Older approved versions remain indexed for manual downgrades.
Suites are codenames, not rolling <code>stable</code> or <code>testing</code> aliases.
This archive is not affiliated with the Debian project.</p>
</section>
<section aria-labelledby="setup">
<h2 id="setup">Adding the repository (when published)</h2>
<p>For Debian <code>{escape(suite)}</code> on AMD64 or ARM64. Use the matching
suite from the table for other Debian versions. Before trusting a
third-party repository, verify its permanent signing key fingerprint
through an independent channel.</p>
<p><strong>1.</strong> Install the production archive key into
<code>/etc/apt/keyrings/</code>:</p>
<pre><code>{escape(key_command)}</code></pre>
<p><strong>2.</strong> Add a deb822 source file with a scoped
<code>Signed-By</code> key (no <code>apt-key</code>):</p>
<pre><code>{escape(sources_command)}</code></pre>
<p><strong>3.</strong> Refresh APT and explicitly select the archive version:</p>
<pre><code>{escape(install_command)}</code></pre>
<p class="small">Only binary packages are provided; no <code>deb-src</code> index.
The repository uses backports-style APT priorities, so installation of an
archive version should be requested explicitly.</p>
</section>
<footer>
<p>Sources: {sources}. <a href="archive-provenance.json">Archive provenance</a>
· <a href="dists/{escape(suite)}/InRelease">Signed release metadata</a>
· <a href="xddd-archive-keyring.gpg">Archive public key (test only)</a>
· <a href="https://github.com/mwyau/apt">Repository builder</a>.</p>
</footer>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', type=Path, required=True)
    args = parser.parse_args()
    (args.site / 'index.html').write_text(render(args.site), encoding='utf-8')


if __name__ == '__main__':
    main()
