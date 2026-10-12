#!/usr/bin/env python3
"""Download the pinned official Linux x64 CLI and verify its recorded checksum."""
import hashlib
import io
import json
import os
import tarfile
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
release = json.loads((root / "upstream/manifest.json").read_text())["cli_archive"]
with urllib.request.urlopen(release["url"], timeout=60) as response:
    archive = response.read()
if hashlib.sha256(archive).hexdigest() != release["sha256"]:
    raise SystemExit("Official CLI archive checksum mismatch")
target = root / ".cache/cx"
target.parent.mkdir(exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
    member = next(m for m in tar.getmembers() if m.name in ("cx", "./cx"))
    if not member.isfile():
        raise SystemExit("CLI archive entry is not a regular file")
    target.write_bytes(tar.extractfile(member).read())
os.chmod(target, 0o755)
print(target)
