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
        with tempfile.TemporaryDirectory() as temp, patch.object(collect, 'get_bytes', side_effect=lambda u, token='': lookup[u]):
            result = collect.collect([second, draft, first], Path(temp), {}, '')
            self.assertEqual(len(result['packages']), 12)
            for suite in collect.SUITES:
                self.assertEqual(len(list((Path(temp) / suite).glob('*.deb'))), 4)
            self.assertEqual(result['releases'], ['netavark-20261029.1', 'netavark-20261030.1'])
            fname = next(iter(result['packages']))
            with self.assertRaisesRegex(collect.CollectionError, 'changed since archive lock'):
                collect.collect([first], Path(temp), {fname: 'f' * 64}, '')

    def test_no_published_releases_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(collect.CollectionError, 'No approved'):
                collect.collect([], Path(temp), {}, '')


if __name__ == '__main__':
    unittest.main()
