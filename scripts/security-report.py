#!/usr/bin/env python3
"""Summarize scanner reports without reproducing potential secret values."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path


def summarize(mode, directory):
    files = (["bandit.json", "trivy-fs.json", "gitleaks-dir.json", "gitleaks-git.json"]
             if mode == "repository" else ["trivy-image.json"])
    lines = ["## Security scan", "",
             "Gate: HIGH/CRITICAL Trivy findings, HIGH Bandit findings, or any Gitleaks secret.",
             "Findings without available fixes are included. Lower severities remain in the reports.",
             "", "| Report | Findings | Blocking |", "| --- | ---: | ---: |"]
    failed = False
    for name in files:
        try:
            data = json.loads((directory / name).read_text())
            if name.startswith("trivy"):
                findings = [v for r in data["Results"] for key in
                            ("Vulnerabilities", "Misconfigurations", "Secrets") for v in r.get(key, [])]
                counts = Counter(v["Severity"] for v in findings)
                blocking = counts["HIGH"] + counts["CRITICAL"]
            elif name == "bandit.json":
                findings = data["results"]
                blocking = sum(v["issue_severity"] == "HIGH" for v in findings)
                if data.get("errors"):
                    raise ValueError("Bandit could not scan all files")
            else:
                if not isinstance(data, list):
                    raise ValueError("Expected a Gitleaks finding list")
                findings = data
                blocking = len(findings)
            lines.append(f"| {name} | {len(findings)} | {blocking} |")
            failed |= blocking > 0
        except (OSError, ValueError, KeyError, TypeError):
            lines.append(f"| {name} | Missing or invalid report | FAIL |")
            failed = True
    lines.extend(["", "**Result: " + ("FAIL" if failed else "PASS") + "**", ""])
    return "\n".join(lines), failed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["repository", "image"])
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    summary, failed = summarize(args.mode, args.directory)
    args.directory.mkdir(parents=True, exist_ok=True)
    (args.directory / f"{args.mode}-summary.md").write_text(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
            output.write(summary)
    print(summary)
    raise SystemExit(int(failed))
