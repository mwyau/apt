"""Offline end-to-end package lifecycle tests using disposable valid Debian packages.

No generated test binary is uploaded or published. These tests exercise the
same collector, aptly builder, and APT verifier as the real-release workflow.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import collect, verify


REPOSITORY = 'example/netavark'


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class ArchiveLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.downloads = {}
        self.releases = []
        self.sources = self.root / 'sources.json'
        self.sources.write_text(json.dumps({
            'schema': 1,
            'sources': [{'repository': REPOSITORY,
                         'format': 'netavark-releases-v1'}],
        }))

    def make_deb(self, revision: int, suite: str, arch: str,
                 payload: str = 'original') -> tuple[str, bytes]:
        version = f'1.14.0-2xddd{revision}~{suite}'
        name = f'netavark_{version}_{arch}.deb'
        base = self.root / 'deb-builds' / str(revision) / payload / suite / arch
        control = base / 'DEBIAN' / 'control'
        control.parent.mkdir(parents=True, exist_ok=True)
        control.write_text(
            f'Package: netavark\nVersion: {version}\nArchitecture: {arch}\n'
            'Maintainer: Test Author <test@example.invalid>\n'
            'Description: Temporary archive lifecycle integration test\n')
        content = base / 'usr' / 'share' / 'doc' / 'netavark' / 'test.txt'
        content.parent.mkdir(parents=True, exist_ok=True)
        content.write_text(f'{version} / {arch} / {payload}\n')
        output = base.parent / f'{payload}-{suite}-{arch}.deb'
        subprocess.run(['dpkg-deb', '--build', '--root-owner-group',
                        str(base), str(output)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        return name, output.read_bytes()

    def make_release(self, tag: str, revision: int, carry: dict | None = None,
                     override: dict | None = None,
                     repo: str = REPOSITORY) -> tuple[dict, dict]:
        manifest = {'debian': {suite: {'source': '1.14.0-2', 'revision': revision}
                               for suite in collect.SUITES}}
        binaries = dict(carry or {})
        for suite in collect.SUITES:
            for arch in collect.ARCHES:
                name, content = self.make_deb(revision, suite, arch)
                binaries[name] = content
        binaries.update(override or {})
        blobs = {'versions.json': json.dumps(manifest, sort_keys=True).encode(), **binaries}
        sums = {name: sha256(data) for name, data in blobs.items()}
        blobs['SHA256SUMS'] = ''.join(
            f'{sha}  {name}\n' for name, sha in sorted(sums.items())
        ).encode()
        assets = []
        for name, content in blobs.items():
            actual = name.replace('~', '.') if name.endswith('.deb') else name
            url = f'https://github.com/{repo}/releases/download/{tag}/{actual}'
            assets.append({
                'name': actual, 'browser_download_url': url,
                'digest': f'sha256:{sha256(content)}',
                'created_at': '2026-10-29T12:00:00Z',
            })
            self.downloads[url] = content
        release = {
            'tag_name': tag, 'draft': False, 'prerelease': False,
            'published_at': '2026-10-29T12:00:00Z',
            'target_commitish': 'abcdef1234',
            'assets': assets,
        }
        return release, binaries

    def run_collector(self, label: str, lock_path: Path,
                      require_locked: bool = True):
        root = self.root / label
        root.mkdir(parents=True, exist_ok=True)
        output = root / 'packages'
        candidate = root / 'package-lock.candidate.json'
        provenance = root / 'archive-provenance.json'
        argv = ['collect.py', '--sources', str(self.sources),
                '--output', str(output), '--lock', str(lock_path),
                '--candidate-lock', str(candidate), '--manifest', str(provenance)]
        if require_locked:
            argv.append('--require-locked')
        with patch.object(collect, 'list_releases',
                          side_effect=lambda repo, token: self.releases), \
             patch.object(collect, 'get_bytes',
                          side_effect=lambda url, token='': self.downloads[url]), \
             patch.object(sys, 'argv', argv):
            collect.main()
        return output, json.loads(candidate.read_text()), provenance

    def write_lock(self, name: str, packages: dict, removed: dict | None = None):
        path = self.root / name
        path.write_text(json.dumps({
            'schema': 2, 'packages': packages, 'removed': removed or {},
        }))
        return path

    def build_and_verify(self, label: str, packages: Path, manifest: Path):
        site = self.root / f'{label}-site'
        subprocess.run(
            ['bash', 'scripts/build/aptly.sh', str(packages), str(site)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        shutil.copyfile(manifest, site / 'archive-provenance.json')
        verify.verify(site, packages)
        return site

    def test_release_approval_removal_restoration_and_multiversion_apt(self):
        old, first_bytes = self.make_release('netavark-20261029.1', 1)
        new, second_bytes = self.make_release('netavark-20261030.1', 2,
                                              carry=first_bytes)
        old_hashes = {name: sha256(data) for name, data in first_bytes.items()}
        new_hashes = {name: sha256(data) for name, data in second_bytes.items()}
        lock_path = self.write_lock('lock.json', old_hashes)
        self.releases = [old]
        packages, candidate, manifest = self.run_collector('initial', lock_path)
        self.assertEqual(candidate['packages'], old_hashes)
        self.assertEqual(sum(len(list((packages / s).glob('*.deb')))
                             for s in collect.SUITES), 6)
        self.assertEqual(set(json.loads(manifest.read_text())['packages']),
                         set(old_hashes))

        self.releases = [new, old]  # discovery must handle reverse API order
        with self.assertRaisesRegex(SystemExit, 'Unreviewed new packages'):
            self.run_collector('not-approved', lock_path)
        self.assertFalse((self.root / 'not-approved' / 'packages').exists(),
                         'Rejected additions must not leave binary output')

        packages, proposal, manifest = self.run_collector(
            'discovery', lock_path, require_locked=False)
        self.assertEqual(proposal['packages'], new_hashes)
        self.assertEqual(set(proposal['removed']), set())
        self.assertEqual(sum(len(list((packages / s).glob('*.deb')))
                             for s in collect.SUITES), 6,
                         'Discovery may collect but must not expose new binaries')

        lock_path = self.write_lock('approved.json', new_hashes)
        packages, candidate, manifest = self.run_collector('approved', lock_path)
        self.assertEqual(candidate['packages'], new_hashes)
        expected = verify.expected_packages(packages)
        self.assertTrue(all(len(expected[(suite, arch)]) == 2
                            for suite in collect.SUITES for arch in collect.ARCHES))
        self.build_and_verify('multiversion', packages, manifest)

        removed_lock = self.write_lock('removed.json',
                                       {k: v for k, v in new_hashes.items()
                                        if k not in old_hashes},
                                       old_hashes)
        packages, candidate, manifest = self.run_collector('removed', removed_lock)
        self.assertEqual(candidate['removed'], old_hashes)
        expected = verify.expected_packages(packages)
        self.assertTrue(all(len(expected[(suite, arch)]) == 1
                            for suite in collect.SUITES for arch in collect.ARCHES))
        self.build_and_verify('removed', packages, manifest)

        packages, candidate, manifest = self.run_collector(
            'restored', self.write_lock('restored.json', new_hashes))
        self.assertEqual(candidate['packages'], new_hashes)
        self.assertTrue(all(len(verify.expected_packages(packages)[(suite, arch)]) == 2
                            for suite in collect.SUITES for arch in collect.ARCHES))

    def test_changed_same_version_requires_review(self):
        old, original = self.make_release('netavark-20261029.1', 1)
        target = sorted(original)[0]
        suite = target.split('~')[1].split('_')[0]
        arch = target.removesuffix('.deb').rsplit('_', 1)[1]
        _name, changed_data = self.make_deb(1, suite, arch, payload='modified')
        new, _ = self.make_release('netavark-20261030.1', 1,
                                   override={target: changed_data})
        self.releases = [new, old]
        old_hashes = {name: sha256(data) for name, data in original.items()}
        lock = self.write_lock('original-lock.json', old_hashes)
        with self.assertRaisesRegex(SystemExit, 'modified='):
            self.run_collector('conflict-rejected', lock)
        self.assertFalse((self.root / 'conflict-rejected' / 'packages').exists())
        packages, candidate, _manifest = self.run_collector(
            'conflict-proposed', lock, require_locked=False)
        self.assertEqual(candidate['packages'][target], sha256(changed_data))
        self.assertEqual(len(list(packages.rglob('*.deb'))), 6)
        evidence = json.loads(
            (self.root / 'conflict-proposed' / 'package-discovery.json').read_text()
        )['packages'][target]
        self.assertEqual(evidence['selected_release'],
                         f'{REPOSITORY}@netavark-20261030.1')
        self.assertEqual([item['sha256'] for item in evidence['hash_history']],
                         [old_hashes[target], sha256(changed_data)])

    def test_different_sources_colliding_fail_closed(self):
        first, binaries = self.make_release('netavark-20261029.1', 1)
        second, _ = self.make_release('netavark-20261029.2', 1,
                                      carry=binaries, repo='example/other')
        def available(repo, _token):
            return [first] if repo == REPOSITORY else [second]
        with patch.object(collect, 'list_releases', side_effect=available), \
             patch.object(collect, 'get_bytes',
                          side_effect=lambda url, token='': self.downloads[url]):
            with self.assertRaisesRegex(
                    collect.CollectionError, 'collision across sources'):
                collect.collect_sources(
                    [REPOSITORY, 'example/other'],
                    self.root / 'multiple-sources', {}, '')


if __name__ == '__main__':
    unittest.main()
