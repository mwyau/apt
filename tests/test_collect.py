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
            result = collect.collect([second, draft, first], Path(temp), {}, '', 'mwyau/netavark-backports')
            self.assertEqual(len(result['packages']), 12)
            for suite in collect.SUITES:
                self.assertEqual(len(list((Path(temp) / suite).glob('*.deb'))), 4)
            self.assertEqual(result['releases'], ['netavark-20261029.1', 'netavark-20261030.1'])
            fname = next(iter(result['packages']))
            with self.assertRaisesRegex(collect.CollectionError, 'changed since archive lock'):
                collect.collect([first], Path(temp), {fname: 'f' * 64}, '', 'mwyau/netavark-backports')

    def test_conflicting_filename_chooses_latest_dated_tag(self):
        manifest = {'debian': {s: {'source': '1.14.0-2', 'revision': 1}
                               for s in collect.SUITES}}
        binaries = {n: (n + ':original').encode()
                    for n in collect.debian_names(manifest)}
        target = sorted(binaries)[0]
        newest_values = dict(binaries)
        newest_values[target] = b'changed bytes under same Debian version'
        old, old_blobs = self.fake_release('netavark-20261029.2', manifest, binaries)
        new, new_blobs = self.fake_release('netavark-20261030.1', manifest, newest_values)
        # A newer date wins even when the input release list is reversed.
        lookup = {
            **{a['browser_download_url']: old_blobs[a['name']] for a in old['assets']},
            **{a['browser_download_url']: new_blobs[a['name']] for a in new['assets']},
        }
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(collect, 'get_bytes',
                             side_effect=lambda url, token='': lookup[url]), \
                patch.object(collect, 'verify_deb_control'):
            result = collect.collect([new, old], Path(temp), {}, '',
                                     'mwyau/netavark-backports')
            self.assertEqual(result['packages'][target], digest(newest_values[target]))
            self.assertEqual(result['selected_tags'][target], 'netavark-20261030.1')
            self.assertEqual(result['provenance'][target], ['netavark-20261030.1'])
            self.assertEqual([e['sha256'] for e in result['hash_history'][target]],
                             [digest(binaries[target]), digest(newest_values[target])])
            self.assertEqual((Path(temp) / 'forky' / target).is_file(),
                             '~forky' in target)
            with self.assertRaisesRegex(collect.CollectionError, 'modified='):
                collect.ensure_locked_subset(result['packages'], {target: digest(binaries[target])})
            candidate = collect.resolve_lock(result['packages'],
                                             {target: digest(binaries[target])}, {}, False)
            self.assertEqual(candidate['packages'][target], digest(newest_values[target]))
            with self.assertRaisesRegex(collect.CollectionError, 'modified='):
                collect.resolve_lock(result['packages'],
                                     {target: digest(binaries[target])}, {}, True)

    def test_latest_tag_run_number_is_numeric(self):
        self.assertLess(collect.release_order('netavark-20261029.9'),
                        collect.release_order('netavark-20261029.10'))
        self.assertLess(collect.release_order('netavark-20261029.99'),
                        collect.release_order('netavark-20261030.1'))

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
            expected, normalized, checksums = collect.validated_release(release, '', 'mwyau/netavark-backports')
        self.assertEqual(set(expected), set(binaries))
        self.assertEqual(set(normalized) - {'versions.json'}, set(binaries))
        self.assertEqual(checksums[next(iter(binaries))],
                         digest(binaries[next(iter(binaries))]))
        release['assets'][1]['digest'] = 'sha256:' + 'f' * 64
        with patch.object(collect, 'get_bytes',
                          side_effect=lambda u, token='': lookup[u]):
            with self.assertRaisesRegex(collect.CollectionError, 'digest conflict'):
                collect.validated_release(release, '', 'mwyau/netavark-backports')

    def test_archive_lock_rejects_bad_names_and_digests(self):
        good = 'netavark_1.14.0-2xddd1~trixie_amd64.deb'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'package-lock.json'
            path.write_text(json.dumps({'schema': 2, 'packages': {good: 'a' * 64}}))
            self.assertEqual(collect.load_lock(path)[good], 'a' * 64)
            path.write_text(json.dumps({'schema': 2, 'packages': {good: 'not-a-sha'}}))
            with self.assertRaisesRegex(collect.CollectionError, 'SHA-256'):
                collect.load_lock(path)
            path.write_text(json.dumps({'schema': 2, 'packages': {
                '../wrong.deb': 'a' * 64}}))
            with self.assertRaisesRegex(collect.CollectionError, 'package name'):
                collect.load_lock(path)

    def test_source_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'sources.json'
            config.write_text(json.dumps({
                'schema': 1, 'sources': [
                    {'repository': 'example/netavark-backports',
                     'format': 'netavark-releases-v1'}]}))
            self.assertEqual(collect.load_sources(config),
                             ['example/netavark-backports'])
            config.write_text(json.dumps({
                'schema': 1, 'sources': [
                    {'repository': '../escape', 'format': 'netavark-releases-v1'}]}))
            with self.assertRaises(collect.CollectionError):
                collect.load_sources(config)

    def test_lock_is_publication_allowlist_with_removed_history(self):
        first = 'netavark_1.14.0-2xddd1~trixie_amd64.deb'
        second = 'netavark_1.14.0-2xddd2~trixie_amd64.deb'
        a, b = 'a' * 64, 'b' * 64
        discovered = {first: a, second: b}
        active = {second: b}
        removed = {first: a}
        candidate = collect.resolve_lock(discovered, active, removed, False)
        self.assertEqual(candidate, {
            'schema': 2, 'packages': active, 'removed': removed})
        self.assertEqual(collect.resolve_lock(discovered, active, removed, True),
                         candidate)
        # Manually restore an old version: move its original hash back to packages.
        restored = collect.resolve_lock(discovered, discovered, {}, True)
        self.assertEqual(restored['packages'], discovered)
        # Remove a new version from the lock; discovery proposes it for review.
        with self.assertRaisesRegex(collect.CollectionError, 'Unreviewed'):
            collect.resolve_lock(discovered, {first: a}, {}, True)
        with self.assertRaisesRegex(collect.CollectionError, 'missing='):
            collect.resolve_lock({second: b}, discovered, {}, True)
        with self.assertRaisesRegex(collect.CollectionError, 'Removed historical package changed'):
            collect.resolve_lock({first: 'f' * 64, second: b}, active, removed, True)
        with self.assertRaisesRegex(collect.CollectionError, 'modified='):
            collect.resolve_lock({first: a, second: 'f' * 64}, active, removed, True)

    def test_removed_history_retained_in_one_lock(self):
        first = 'netavark_1.14.0-2xddd1~trixie_amd64.deb'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'package-lock.json'
            path.write_text(json.dumps({
                'schema': 2, 'packages': {}, 'removed': {first: 'a' * 64}}))
            active, removed = collect.load_lock_state(path)
            self.assertEqual(active, {})
            self.assertEqual(removed[first], 'a' * 64)
            path.write_text(json.dumps({
                'schema': 2, 'packages': {first: 'a' * 64},
                'removed': {first: 'a' * 64}}))
            with self.assertRaisesRegex(collect.CollectionError, 'both enabled'):
                collect.load_lock_state(path)

    def test_no_published_releases_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(collect.CollectionError, 'No approved'):
                collect.collect([], Path(temp), {}, '', 'mwyau/netavark-backports')


if __name__ == '__main__':
    unittest.main()
