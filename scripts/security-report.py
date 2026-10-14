#!/usr/bin/env python3
"""Summarize scanner reports without reproducing potential secret values."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re


def reviewed_false_positive(target, finding, source_root):
    # KSV-0109 matches "Token: false" inside an embedded Kubernetes manifest.
    # Match the complete message so any additional secret-like key still blocks.
    matched = (target == "api-mock/k8s/cli-smoke.yaml" and
            finding.get("ID") == "KSV-0109" and
            finding.get("Message") ==
            "ConfigMap 'checkmarx-mock-source' in 'checkmarx-mock' namespace stores secrets in key(s) or value(s) "
            "'{\"      automountServiceAccountToken\"}'")
    if not matched:
        return False
    try:
        source = (source_root / target).read_text()
    except OSError:
        return False
    values = re.findall(r"(?m)^\s*automountServiceAccountToken\s*:\s*([^\n]+)$", source)
    return bool(values) and all(value.strip() == "false" for value in values)


def summarize(mode, directory, source_root=None):
    source_root = Path.cwd() if source_root is None else source_root
    files = (["bandit.json", "trivy-fs.json", "gitleaks-dir.json", "gitleaks-git.json"]
             if mode == "repository" else ["trivy-image.json"])
    lines = ["## Security scan", "",
             "Gate: HIGH/CRITICAL Trivy findings, HIGH Bandit findings, or any Gitleaks secret.",
             "Findings without available fixes are included. Lower severities remain in the reports.",
             "", "| Report | Findings | Blocking |", "| --- | ---: | ---: |"]
    failed = False
    reviews = []
    for name in files:
        try:
            data = json.loads((directory / name).read_text())
            if name.startswith("trivy"):
                findings = [v for r in data["Results"] for key in
                            ("Vulnerabilities", "Misconfigurations", "Secrets") for v in r.get(key, [])]
                counts = Counter(v["Severity"] for v in findings)
                blocking = counts["HIGH"] + counts["CRITICAL"]
                for result in data["Results"]:
                    for finding in result.get("Misconfigurations", []):
                        if reviewed_false_positive(result.get("Target", ""), finding, source_root):
                            if finding.get("Severity") in ("HIGH", "CRITICAL"):
                                blocking -= 1
                            reviews.append("Reviewed KSV-0109 false positive in api-mock/k8s/cli-smoke.yaml: "
                                           "automountServiceAccountToken is a boolean set to false, not a secret. "
                                           "The original finding remains in the JSON report.")
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
    lines.extend(["", *reviews, "", "**Result: " + ("FAIL" if failed else "PASS") + "**", ""])
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
