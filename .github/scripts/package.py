#!/usr/bin/env python3
"""Package a release binary as pocketbase-rs_<version>_<os>_<arch>.zip.

The archive contains the binary plus CHANGELOG.md, LICENSE.md and README.md at
its root, so extracting it yields a ready-to-run directory.
"""

from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path

VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="compiled binary")
    parser.add_argument("--version", required=True, help="release version, e.g. 0.1.1")
    parser.add_argument("--os", dest="os_name", required=True, choices=("darwin", "linux", "windows"))
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--out-dir", type=Path, default=Path("dist"))
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument("--license", type=Path, default=Path("LICENSE.md"))
    parser.add_argument("--readme", type=Path, default=Path("README.md"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not VERSION_RE.match(args.version):
        print(f"error: invalid version '{args.version}'", file=sys.stderr)
        return 1
    if not args.binary.is_file():
        print(f"error: binary not found: {args.binary}", file=sys.stderr)
        return 1
    if not args.changelog.is_file():
        print(f"error: changelog not found: {args.changelog}", file=sys.stderr)
        return 1
    if not args.license.is_file():
        print(f"error: license not found: {args.license}", file=sys.stderr)
        return 1

    files = [args.binary, args.changelog, args.license]
    if args.readme.is_file():
        files.append(args.readme)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    archive = args.out_dir / (
        f"pocketbase-rs_{args.version}_{args.os_name}_{args.arch}.zip"
    )

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            zf.write(path, arcname=path.name)

    print(f"created {archive} ({archive.stat().st_size} bytes)")
    for path in files:
        print(f"  + {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
