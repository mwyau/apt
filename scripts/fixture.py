#!/usr/bin/env python3
"""Generate harmless synthetic Debian packages to exercise multi-version APT indexes."""
from __future__ import annotations
import argparse
import subprocess
import tempfile
from pathlib import Path

SUITES = ('trixie', 'forky', 'sid')
ARCHES = ('amd64', 'arm64')


def generate(out: Path) -> None:
    for suite in SUITES:
        for arch in ARCHES:
            for revision in (1, 2):
                version = f'0.0.1-xdddtest{revision}~{suite}'
                folder = out / suite
                folder.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    control = root / 'DEBIAN' / 'control'
                    control.parent.mkdir()
                    control.write_text(f'Package: xddd-apt-test-fixture\nVersion: {version}\nArchitecture: {arch}\nMaintainer: XDDD CI <ci@example.invalid>\nDescription: Non-functional APT repository test fixture\n')
                    (root / 'usr/share/doc/xddd-apt-test-fixture').mkdir(parents=True)
                    (root / 'usr/share/doc/xddd-apt-test-fixture/README').write_text('TEST ONLY: not a real Netavark package.\n')
                    name = f'xddd-apt-test-fixture_{version}_{arch}.deb'
                    subprocess.run(['dpkg-deb', '--build', '--root-owner-group', str(root), str(folder / name)], check=True, stdout=subprocess.DEVNULL)
    print('Generated 12 harmless test packages (3 suites x 2 architectures x 2 versions)')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, required=True)
    generate(p.parse_args().output)
