# XDDD APT archive builder

Build a **test-signed**, static Debian APT repository from approved releases of
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
3. Checks historical package checksums against `archive-lock.json`, rejects
   conflicting or disappearing packages, and retains every approved version
   for later downgrades.
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
[`archive-lock.json`](archive-lock.json). The lock is independent of editable
GitHub Releases. If a previously approved package's bytes change, or a locked
version disappears from release history, the build stops.

When a new approved release adds packages, the build writes
`archive-lock.candidate.json` to its Actions artifact. Review and commit the
updated hashes in a separate PR. This repository never silently changes the
committed lock.

GitHub Release storage may replace the `~` in `.deb` **asset filenames** with
`.`. The collector maps those names back to their checksummed canonical
filenames while preserving the `~trixie`, `~forky`, and `~sid` **Debian package
versions**. Ubuntu, RPM and source artifacts are excluded from this APT archive.

## Local development

Requirements: Python 3, `aptly`, `gnupg`, `gpgv`, `dpkg-dev` and `apt-get`.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/collect.py \
  --output .artifacts/packages \
  --lock archive-lock.json \
  --candidate-lock .artifacts/archive-lock.candidate.json \
  --manifest .artifacts/archive-provenance.json
bash scripts/build.sh .artifacts/packages .artifacts/site
cp .artifacts/archive-provenance.json .artifacts/site/archive-provenance.json
python3 scripts/verify.py --site .artifacts/site --packages .artifacts/packages
```

To access a GitHub API token when needed for rate limits, set `GH_TOKEN` in
the environment. Only published public release files are downloaded, and
credentials are not forwarded to their download URLs.

## Later deployment (not implemented)

The intended hostname is `apt.xddd.org`. A later phase will configure a
production signing key, review publication security and optionally deploy
the generated tree to Cloudflare Pages Free. No Cloudflare project or secrets
are required for this initial build.
