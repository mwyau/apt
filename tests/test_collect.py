import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import collect


def digest(content):
    return hashlib.sha256(content).hexdigest()


class CollectorTests(unittest.TestCase):
    def test_names_match_backports_versioning(self):
        v = {'debian': {'trixie': {'source': '1.14.0-2+deb13u1', 'revision': 2},
                        'forky': {'source': '1.17.2-3', 'revision': 1},
                        'sid': {'source': '1.17.2-3', 'revision': 1}}}
        names = collect.debian_names(v)
        self.assertIn('netavark_1.14.0-2+deb13u1xddd2~trixie_amd64.deb', names)
        self.assertEqual(len(names), 6)

    def test_reject_bad_checksums(self):
        self.assertRaises(collect.CollectionError, collect.checksums_from_bytes, b'123  bad\n')
        line = digest(b'a') + '  netavark.deb\n'
        self.assertRaises(collect.CollectionError, collect.checksums_from_bytes, (line * 2).encode())

    def fake_release(self, tag, manifest, values, draft=False):
        blobs = {'versions.json': json.dumps(manifest).encode()}
        blobs.update(values)
        checksums = {name: digest(value) for name, value in blobs.items()}
        blobs['SHA256SUMS'] = ''.join(f'{s}  {n}\n' for n, s in sorted(checksums.items())).encode()
        result = {'tag_name': tag, 'draft': draft, 'prerelease': False, 'assets': [
            {'name': name, 'browser_download_url': f'https://github.com/mwyau/netavark-backports/releases/download/{tag}/{name}'}
            for name in blobs]}
        return result, blobs

    def test_snapshots_deduplicate_and_retain_all_versions(self):
        manifest1 = {'debian': {s: {'source': '1.14.0-2', 'revision': 1} for s in collect.SUITES}}
        manifest2 = {'debian': {s: {'source': '1.14.0-2', 'revision': 2} for s in collect.SUITES}}
        def values(manifest):
            return {n: (n + ':bytes').encode() for n in collect.debian_names(manifest)}
        first, blobs1 = self.fake_release('netavark-20261029.1', manifest1, values(manifest1))
        second, blobs2 = self.fake_release('netavark-20261030.1', manifest2, {**values(manifest1), **values(manifest2)})
        draft, _ = self.fake_release('netavark-20261031.1', manifest2, {}, draft=True)
        lookup = {**{a['browser_download_url']: blobs1[a['name']] for a in first['assets']},
                  **{a['browser_download_url']: blobs2[a['name']] for a in second['assets']}}
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(collect, 'get_bytes', side_effect=lambda u, token='': lookup[u]), \
                patch.object(collect, 'verify_deb_control'):
            result = collect.collect([second, draft, first], Path(temp), {}, '')
            self.assertEqual(len(result['packages']), 12)
            for suite in collect.SUITES:
                self.assertEqual(len(list((Path(temp) / suite).glob('*.deb'))), 4)
            self.assertEqual(result['releases'], ['netavark-20261029.1', 'netavark-20261030.1'])
            fname = next(iter(result['packages']))
            with self.assertRaisesRegex(collect.CollectionError, 'changed since archive lock'):
                collect.collect([first], Path(temp), {fname: 'f' * 64}, '')

    def test_package_control_requires_exact_name_version_arch(self):
        with patch.object(collect.subprocess, 'check_output',
                          return_value='Package: netavark\nVersion: 1.14.0-2xddd1~trixie\nArchitecture: amd64\n'):
            collect.verify_deb_control(Path('netavark.deb'), 'trixie', 'amd64',
                                       '1.14.0-2xddd1~trixie')
            with self.assertRaisesRegex(collect.CollectionError, 'Control metadata mismatch'):
                collect.verify_deb_control(Path('netavark.deb'), 'trixie', 'arm64',
                                           '1.14.0-2xddd1~trixie')

    def test_normalized_github_asset_names_are_hash_verified(self):
        manifest = {'debian': {s: {'source': '1.14.0-2', 'revision': 1}
                               for s in collect.SUITES}}
        binaries = {n: (n + ':bytes').encode() for n in collect.debian_names(manifest)}
        release, blobs = self.fake_release('netavark-20261029.1', manifest, binaries)
        for asset in release['assets']:
            original = asset['name']
            if original.endswith('.deb'):
                asset['name'] = original.replace('~', '.')
            asset['digest'] = 'sha256:' + digest(blobs[original])
        lookup = {a['browser_download_url']: blobs[
            a['browser_download_url'].rsplit('/', 1)[-1]]
            for a in release['assets']}
        with patch.object(collect, 'get_bytes',
                          side_effect=lambda u, token='': lookup[u]):
            expected, normalized, checksums = collect.validated_release(release, '')
        self.assertEqual(set(expected), set(binaries))
        self.assertEqual(set(normalized) - {'versions.json'}, set(binaries))
        self.assertEqual(checksums[next(iter(binaries))],
                         digest(binaries[next(iter(binaries))]))
        release['assets'][1]['digest'] = 'sha256:' + 'f' * 64
        with patch.object(collect, 'get_bytes',
                          side_effect=lambda u, token='': lookup[u]):
            with self.assertRaisesRegex(collect.CollectionError, 'digest conflict'):
                collect.validated_release(release, '')

    def test_no_published_releases_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(collect.CollectionError, 'No approved'):
                collect.collect([], Path(temp), {}, '')


if __name__ == '__main__':
    unittest.main()
