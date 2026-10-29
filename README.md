# XDDD APT archive builder

Build a **test-signed**, static Debian APT repository from published releases of repositories configured in
[`archive/sources.json`](archive/sources.json). The first configured source is
[`mwyau/netavark-backports`](https://github.com/mwyau/netavark-backports).
This repository **does not deploy an APT website** or publish packages to a public mirror.

## Build

The [Build signed APT archive workflow](.github/workflows/build.yml) runs on pull
requests, pushes to `main`, and manual dispatch. It:

1. Lists all published, non-draft, non-prerelease `netavark-YYYYMMDD.N` releases.
   Draft `ci-*` releases are never eligible.
2. Downloads the release manifests and checksum lists, verifies their consistency,
   and selects only Debian Trixie, Forky and Sid `netavark` binaries for
   `amd64` and `arm64`.
3. Checks historical package checksums against `archive/package-lock.json`, rejects
   conflicting or disappearing packages, **and refuses unreviewed new binaries**.
   Every approved version remains available for later downgrades.
4. Uses **aptly** to generate the complete `dists/` and `pool/` tree,
   signed `InRelease`, `Release`, `Release.gpg`, architecture package indexes
   and by-hash index files.
5. Verifies index entries, binary checksums, signatures and repository priority
   fields; runs `apt-get update` separately against Trixie, Forky and Sid.
6. Adds `archive-provenance.json` to the site, documenting all approved
   source releases, each binary's SHA-256 digest, and the original GitHub
   asset-upload date. This metadata is informational; it does not substitute
   for repository signatures or checksum verification.
7. Uploads `apt-site.tar.gz`, `apt-site.tar.gz.sha256` and the candidate
   updated checksum lock as a GitHub Actions artifact called `apt-site`.

The latest approved release is discovered automatically. The initial source
release is [`netavark-20261029.1`](https://github.com/mwyau/netavark-backports/releases/tag/netavark-20261029.1),
with six Debian binaries (three distributions and two architectures).

## Signing: test use only

A fresh Ed25519 OpenPGP signing key is generated **inside each CI run** and expires
after 14 days. Its private material remains in a temporary GnuPG directory,
is removed before the archive is uploaded, and is never committed, attached,
or displayed. Only the corresponding **public** key is included in the output.

**Do not install packages from the generated archive on production systems.**
The test signing key is not a stable trust anchor. Before publishing the archive
to `apt.xddd.org`, replace it with a separately protected production APT
signing subkey and complete a deployment review.

## Historical packages and checksum lock

The first release's six Debian SHA-256 digests are recorded in
[`archive/package-lock.json`](archive/package-lock.json). The lock is independent of editable
GitHub Releases. If a previously approved package's bytes change, or a locked
version disappears from release history, the build stops.

A separate [daily discovery workflow](.github/workflows/discover.yml) runs at
08:17 UTC and can also be dispatched manually. It reads `archive/sources.json`,
scans published upstream releases, checks package bytes and control fields,
and opens a PR changing only `archive/package-lock.json` when newly discovered
package hashes are not already enabled or disabled. It never silently replaces existing locked package bytes.
Only one automatic lock-update PR is kept open at a time. If a source release
contains no new binary versions, there is no package-lock PR.

**Review and merge that PR before building the newly discovered versions.**
The main build requires its complete discovered package set to match the
committed lock exactly. The daily checker needs GitHub Actions permission to
create pull requests in this repository (Settings > Actions > General).
PR workflows created using `GITHUB_TOKEN` may require manual **Approve workflows
to run** in the PR UI. No production signing or deployment is triggered by
this stage.

GitHub Release storage may replace the `~` in `.deb` **asset filenames** with
`.`. The collector maps those names back to their checksummed canonical
filenames while preserving the `~trixie`, `~forky`, and `~sid` **Debian package
versions**. Ubuntu, RPM and source artifacts are excluded from this APT archive.

## Remove or recover a published version

[`archive/package-lock.json`](archive/package-lock.json) is the **publication
allowlist**, not simply a log of everything upstream offers. It has two maps:

- `packages`: enabled, reviewed package filenames and SHA-256 values
  included in each generated APT archive.
- `disabled`: previously approved versions intentionally excluded from
  publication, retaining their original reviewed hashes.

To **remove** a version, move its filename and unchanged SHA-256 from
`packages` into `disabled` and merge a reviewed PR. To **recover** it, move
that exact entry back to `packages`. The next build downloads the original
upstream binary, checks its SHA-256 and Debian control fields, and publishes
it only if the hash matches the lock.

Do **not** simply delete the record: without its disabled-history entry,
scheduled discovery would propose the old upstream package again. A disabled
entry prevents that. Re-enabling a missing or changed upstream asset fails
closed. At least one package for each supported Debian suite and architecture
is currently required by the APT builder.

The daily discovery job proposes only packages absent from **both** maps.
Production publication remains a separate, future approval-gated operation.

## Local development

Requirements: Python 3, `aptly`, `gnupg`, `gpgv`, `dpkg-dev` and `apt-get`.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/collect.py \
  --sources archive/sources.json \
  --output .artifacts/packages \
  --lock archive/package-lock.json \
  --require-locked \
  --candidate-lock .artifacts/package-lock.candidate.json \
  --manifest .artifacts/archive-provenance.json
bash scripts/build/aptly.sh .artifacts/packages .artifacts/site
cp .artifacts/archive-provenance.json .artifacts/site/archive-provenance.json
python3 scripts/verify.py --site .artifacts/site --packages .artifacts/packages
```

To access a GitHub API token when needed for rate limits, set `GH_TOKEN` in
the environment. Only published public release files are downloaded, and
credentials are not forwarded to their download URLs.

## Later deployment (not implemented)

The intended hostname is `apt.xddd.org`. **PR approval and publication
approval are separate decisions.** After merging a package-lock PR, the
existing `main` build produces a verified *test-signed* archive artifact.
A later production release workflow should use an `apt-publish` GitHub
Environment restricted to protected `main`, with required reviewers and the
production signing subkey and Cloudflare credentials held in environment
secrets. That workflow must re-download and revalidate every committed hash
before signing and deploying. No Cloudflare project or production secrets
are required for the current stage.
