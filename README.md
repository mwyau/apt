# XDDD APT repository builder

Generate a **test-signed** Debian APT archive from approved releases in
[`mwyau/netavark-backports`](https://github.com/mwyau/netavark-backports).
This project does **not** publish any website or packages yet.

## First-stage workflow

[Build signed APT archive](.github/workflows/build.yml) runs on PRs and on
`main`, building **both** the synthetic fixture and the real approved release archive in separate matrix jobs. Manual dispatch runs both modes as well:

- **`fixture`**: creates 12 **non-functional** `xddd-apt-test-fixture`
  packages: two versions for three Debian suites and two architectures. No
  downloads or approved release required. Never install these as Netavark.
- **`releases`**: enumerates all published, non-draft, non-prerelease
  `netavark-YYYYMMDD.N` GitHub Releases; reads `versions.json` and
  `SHA256SUMS` from each; verifies hashes; selects only Debian Trixie,
  Forky and Sid AMD64/ARM64 `.deb` packages. It retains every distinct
  historical version and fails if no approved releases exist. Existing
  `ci-*` draft releases are **not** accepted.

The output is a `apt-site.tar.gz` GitHub Actions artifact containing `dists/`,
`pool/`, a public keyring and an HTML warning. Every suite gets signed `Release`,
`Release.gpg`, `InRelease`, architecture indexes, and by-hash indexes generated
by **aptly**. The workflow validates package hashes and signatures and runs a
real `apt-get update` against the local file-based archive before uploading it.
No Cloudflare setup, persistent database, persistent GPG key, or deployment
credential is needed.

## Temporary signing key

Each run generates a new Ed25519 test-only OpenPGP signing key expiring in 14
days. It is created inside an isolated temporary `GNUPGHOME`, and its private
material is deleted before output is archived. **Do not trust, publish, or
install from this archive in production.** The `xddd-archive-keyring.gpg` inside
the output is a *public* key only. In particular, it must not be deployed to
`apt.xddd.org` or distributed as a permanent trust anchor.

## Historical packages and edit protection

The release collector checks all published historical release snapshots,
including the binaries carried forward by Netavark's release pipeline, and
eliminates duplicate `(package filename, SHA256)` combinations. If a repeated
filename has different bytes, the build fails. If a previously approved
package has its checksum recorded in `archive-lock.json`, the build fails if
that package changes **or disappears**.

The six Debian binaries from the first approved release
[`netavark-20261029.1`](https://github.com/mwyau/netavark-backports/releases/tag/netavark-20261029.1)
are already recorded in `archive-lock.json`. These SHA-256 values remain a
reviewed source of truth independent of editable GitHub Releases.

When later releases add binaries, review the produced
`archive-lock.candidate.json` and update `archive-lock.json` in a PR.
**This workflow never updates its lock automatically.**

The source Release artifact's snapshot filenames are derived from its
`versions.json`. GitHub replaces the `~` in Debian binary release asset
filenames with `.`; this is *only* a download filename change, not a Debian
package version change. The collector checks the original canonical name in
`SHA256SUMS` and restores the canonical `~suite` filename locally.
Do not change the package `Version` field to work around GitHub filenames. Only `.deb` binaries are published: source packages stay in
upstream GitHub Releases. The backports project controls which releases are
approved; this repository never promotes drafts or substitutes synthetic
packages into `releases` mode.

## Local development

Requires `python3`, `dpkg-deb`, `aptly`, `gpg`, `gpgv`, and `apt-get`.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/fixture.py --output .artifacts/packages
bash scripts/build.sh .artifacts/packages .artifacts/site
python3 scripts/verify.py --site .artifacts/site --mode fixture
```

`aptly` owns the Debian archive format and checksums. No handcrafted `Packages`
or `Release` indexes are used. The generated site is **not** committed to Git.

## Planned deployment (out of scope)

When planning the later production deployment, replace the ephemeral test signer with a protected production signing
subkey, implement a fully reviewed archive lock, and add a separately approved
Cloudflare Pages deployment. `apt.xddd.org` remains a proposed hostname, not
a configured domain.