#!/usr/bin/env python3
"""Download the pinned official Linux x64 CLI and verify its recorded checksum."""
import hashlib
import argparse
import io
import json
import os
import tarfile
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output-dir", type=Path, default=root / ".cache",
                    help="Runner build context (default: api-mock/.cache)")
args = parser.parse_args()
manifest = json.loads((root / "upstream/manifest.json").read_text())
release = manifest["cli_archive"]
with urllib.request.urlopen(release["url"], timeout=60) as response:
    archive = response.read()
if hashlib.sha256(archive).hexdigest() != release["sha256"]:
    raise SystemExit("Official CLI archive checksum mismatch")
# Verify the accompanying notices before preparing a distributable build context.
notices = {}
for name in ("LICENSE", "THIRD_PARTY_LICENSES.txt", "licenses/github.com_alexbrainman_sspi_LICENSE"):
    data = (root / "upstream/ast-cli" / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest["files"][name]:
        raise SystemExit(f"CLI license checksum mismatch: {name}")
    notices[name] = data
target = args.output_dir / "cx"
target.parent.mkdir(parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
    member = next(m for m in tar.getmembers() if m.name in ("cx", "./cx"))
    if not member.isfile():
        raise SystemExit("CLI archive entry is not a regular file")
    target.write_bytes(tar.extractfile(member).read())
os.chmod(target, 0o755)
for name, data in notices.items():
    destination = args.output_dir / "legal" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
print(target)
