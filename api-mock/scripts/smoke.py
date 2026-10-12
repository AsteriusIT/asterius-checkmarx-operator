#!/usr/bin/env python3
"""Exercise the real CLI against a running, dedicated WireMock instance.

Resets this mock's mappings, scenarios and request journal. Never use a shared mock.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--url", default="http://127.0.0.1:18080")
parser.add_argument("--cx", default=str(ROOT / ".cache/cx"))
parser.add_argument("--evidence", type=Path)
args = parser.parse_args()
base = args.url.rstrip("/")
cx = str(Path(args.cx).resolve())

def api(path, data=None, method=None):
    request = urllib.request.Request(base + path, data=None if data is None else json.dumps(data).encode(),
                                     method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read()
        return json.loads(body) if body else None

def reset():
    api("/__admin/reset", {}, "POST")

def run(source, engines="sast,sca,iac-security", secret="mock-secret", expect=0, image=None):
    with tempfile.TemporaryDirectory(prefix="cx-api-mock-") as folder:
        env = {k: v for k, v in os.environ.items() if not k.startswith("CX_")}
        env.update(HOME=folder, USER="cx", CX_BASE_URI=base, CX_BASE_AUTH_URI=base, CX_TENANT="mock",
                   CX_CLIENT_ID="mock-cli", CX_CLIENT_SECRET=secret)
        command = [cx, "scan", "create", "--project-name", "mock-project", "--branch", "main",
                   "-s", source, "--scan-types", engines, "--wait-delay", "1", "--retry", "0"]
        if image:
            command.extend(["--container-images", image])
        result = subprocess.run(command, env=env, cwd=folder, text=True, capture_output=True, timeout=90)
        if (result.returncode == 0) != (expect == 0):
            raise AssertionError(f"Unexpected exit {result.returncode}:\n{result.stdout}\n{result.stderr}")
        if "panic:" in result.stderr:
            raise AssertionError(result.stderr)
        return result

def journal():
    entries = api("/__admin/requests")["requests"]
    assert not api("/__admin/requests/unmatched")["requests"], "Unmatched HTTP requests"
    assert all(e.get("stubMapping", {}).get("name") != "unauthorized-or-unimplemented" for e in entries), \
        "CLI used an unimplemented endpoint"
    # Retain only request method/path, response status and fixture name (no tokens or uploads).
    return [{"method": e["request"]["method"], "url": e["request"]["url"],
             "status": e["responseDefinition"]["status"], "fixture": e.get("stubMapping", {}).get("name")}
            for e in reversed(entries)]

results = {"cli_version": subprocess.check_output([cx, "version"], text=True).strip(), "cases": []}
try:
    for name, source, engines in [("repository", "https://github.com/Checkmarx/ast-cli", "sast,sca,iac-security"),
                                   ("local-directory", str(ROOT / "fixtures/source"), "iac-security")]:
        reset()
        result = run(source, engines)
        entries = journal()
        names = [e["fixture"] for e in entries]
        assert all(n in names for n in ["project-create", "scan-create", "scan-running", "scan-completed", "results"]), names
        assert "scan-summary" in names or "sca-export-create" in names, names
        if name == "local-directory":
            assert "upload-url" in names and "upload" in names
            uploads = [e for e in api("/__admin/requests")["requests"] if e["request"]["url"] == "/mock-upload/source.zip"]
            assert uploads and uploads[0]["request"]["bodyAsBase64"].startswith("UEs"), "Expected ZIP upload"
        results["cases"].append({"name": name, "exit_code": result.returncode, "requests": entries})
        # Verify the CLI can reuse an existing project in the same scenario.
        if name == "repository":
            run(source, engines)
            assert "project-search-existing" in [e["fixture"] for e in journal()]
        print(f"PASS {name}")
    reset()
    image = "docker.io/library/nginx@sha256:" + "a" * 64
    result = run(str(ROOT / "fixtures/source"), "container-security", image=image)
    submissions = [e for e in api("/__admin/requests")["requests"]
                   if e["request"]["method"] == "POST" and e["request"]["url"] == "/api/scans"]
    configs = json.loads(submissions[0]["request"]["body"])["config"]
    assert {"type": "containers", "value": {"userCustomImages": image}} in configs, configs
    results["cases"].append({"name": "container-image", "exit_code": result.returncode, "requests": journal()})
    print("PASS container image digest submitted to container-security engine")
    reset()
    api("/__admin/mappings", json.loads((ROOT / "fixtures/failed-scan.json").read_text()), "POST")
    failed = run(str(ROOT / "fixtures/source"), "iac-security", expect=1)
    assert "scan did not complete successfully" in failed.stderr + failed.stdout
    results["cases"].append({"name": "failed-scan", "exit_code": failed.returncode, "requests": journal()})
    print("PASS failed scan produces nonzero CLI exit")
    reset()
    rejected = run(str(ROOT / "fixtures/source"), "iac-security", secret="wrong-secret", expect=1)
    results["cases"].append({"name": "invalid-credentials", "exit_code": rejected.returncode, "requests": journal()})
    print("PASS invalid credentials rejected")
finally:
    reset()
if args.evidence:
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(results, indent=2) + "\n")
