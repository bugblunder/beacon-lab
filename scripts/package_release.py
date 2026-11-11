"""Build a checked source ZIP; keep generated checksum metadata out of Git."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

from check_repository import ROOT, check


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    paths, problems = check()
    if problems:
        raise ValueError("Repository checks failed:\n" + "\n".join(problems))
    version = re.search(r'__version__ = "([^"]+)"', (ROOT / "beaconlab/__init__.py").read_text()).group(1)
    archive_name = f"beaconlab-v{version}.zip"
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / archive_name
    checksums = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in paths}
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for path in paths:
            output.write(path, "beaconlab/" + path.relative_to(ROOT).as_posix())
        output.writestr("beaconlab/RELEASE_SHA256.json", json.dumps({
            "version": version, "purpose": "Exact source-release file hashes; excludes this manifest",
            "files": checksums}, indent=2) + "\n")
    with zipfile.ZipFile(archive) as output:
        if output.testzip() is not None:
            raise ValueError("Archive CRC verification failed")
        for name, digest in checksums.items():
            if hashlib.sha256(output.read("beaconlab/" + name)).hexdigest() != digest:
                raise ValueError(f"Archive hash verification failed: {name}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (args.output / (archive_name + ".sha256")).write_text(f"{digest}  {archive_name}\n")
    print(f"Created {archive_name}: {len(paths)} source files plus generated checksum manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
