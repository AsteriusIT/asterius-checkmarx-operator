#!/usr/bin/env python3
"""Verify vendored official contracts, or restore them from the pinned Git commit."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "upstream/manifest.json").read_text())
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--restore", action="store_true", help="Download the pinned commit and restore vendored files")
args = parser.parse_args()
target = root / "upstream/ast-cli"
if args.restore:
    with tempfile.TemporaryDirectory(prefix="cx-official-contracts-") as folder:
        subprocess.run(["git", "init", "--quiet", folder], check=True)
        subprocess.run(["git", "-C", folder, "fetch", "--quiet", "--depth=1", manifest["repository"], manifest["commit"]], check=True)
        subprocess.run(["git", "-C", folder, "checkout", "--quiet", "FETCH_HEAD"], check=True)
        for path in manifest["files"]:
            destination = target / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(Path(folder) / path, destination)
actual = {str(p.relative_to(target)): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in target.rglob("*") if p.is_file()}
if actual != manifest["files"]:
    raise SystemExit("Vendored API contracts differ from upstream/manifest.json")
print(f"Verified {len(actual)} unmodified official files at {manifest['commit']}")
