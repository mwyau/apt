#!/usr/bin/env bash
# Create a signed, static APT archive entirely within the supplied output directory.
set -Eeuo pipefail
if [[ $# != 2 ]]; then echo 'Usage: scripts/build.sh PACKAGES_DIR OUTPUT_DIR' >&2; exit 2; fi
PACKAGES="$(realpath "$1")"
OUTPUT="$(realpath -m "$2")"
WORK="$(mktemp -d)"
umask 077
export GNUPGHOME="$WORK/gnupg"
mkdir -p "$GNUPGHOME" "$WORK/aptly" "$OUTPUT"
chmod 700 "$GNUPGHOME"
cleanup() { gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

# No CI secret and no long-lived private key. This signature is ONLY for validating the build.
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
  'XDDD APT CI TEST ONLY <ci@example.invalid>' ed25519 sign 14d >/dev/null 2>&1
FINGERPRINT="$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" {print $10; exit}')"
[[ "$FINGERPRINT" =~ ^[A-F0-9]{40}$ ]] || { echo 'Failed to generate test signing key' >&2; exit 1; }
gpg --batch --export "$FINGERPRINT" > "$OUTPUT/xddd-archive-keyring.gpg"
printf '%s\n' "TEST KEY ONLY: $FINGERPRINT (expires in 14 days; never trust as a production key)" > "$OUTPUT/TEST-KEY-NOT-FOR-PRODUCTION.txt"

cat > "$WORK/aptly.conf" <<EOF
{"rootDir":"$WORK/aptly","architectures":["amd64","arm64"]}
EOF
AP=(aptly "-config=$WORK/aptly.conf")
for suite in trixie forky sid; do
  [[ -d "$PACKAGES/$suite" ]] || { echo "Missing package suite $suite" >&2; exit 1; }
  compgen -G "$PACKAGES/$suite/*.deb" >/dev/null || { echo "No .deb files for $suite" >&2; exit 1; }
  "${AP[@]}" repo create "-distribution=$suite" -component=main "xddd-$suite"
  "${AP[@]}" repo add "xddd-$suite" "$PACKAGES/$suite"
  "${AP[@]}" snapshot create "xddd-$suite-snapshot" from repo "xddd-$suite"
  "${AP[@]}" publish snapshot -batch "-gpg-key=$FINGERPRINT" \
    -architectures=amd64,arm64 "-distribution=$suite" -component=main \
    -origin=XDDD -label='XDDD Test APT Repository' \
    -notautomatic=yes -butautomaticupgrades=yes -skip-contents -acquire-by-hash \
    "xddd-$suite-snapshot"
done
cp -a "$WORK/aptly/public/." "$OUTPUT/"
cat > "$OUTPUT/index.html" <<'EOF'
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>XDDD APT archive (test signed)</title></head>
<body><h1>XDDD APT build artifact</h1><p>Unpublished, test-signed CI output. Not a production repository.</p></body></html>
EOF
# Never export or archive a private key.
if find "$OUTPUT" -type f \( -name '*.key' -o -name 'private-keys-v1.d' \) | grep -q .; then
  echo 'Refusing to archive a private key' >&2; exit 1
fi
printf 'Created signed archive in %s (TEST KEY ONLY)\n' "$OUTPUT"
