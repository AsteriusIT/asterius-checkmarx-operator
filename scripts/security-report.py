#!/usr/bin/env python3
"""Summarize scanner reports without reproducing potential secret values."""
import argparse
import json
import os
from pathlib import Path


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
    values = []
    for line in source.splitlines():
        key, separator, value = line.strip().partition(":")
        if separator and key == "automountServiceAccountToken":
            values.append(value.strip())
    return bool(values) and all(value == "false" for value in values)


REVIEW_NOTE = ("Reviewed KSV-0109 false positive in api-mock/k8s/cli-smoke.yaml: "
               "automountServiceAccountToken is a boolean set to false, not a secret. "
               "The original finding remains in the JSON report.")


def trivy_findings(data, source_root):
    findings = []
    blocking = 0
    reviews = []
    for result in data["Results"]:
        for key in ("Vulnerabilities", "Misconfigurations", "Secrets"):
            for finding in result.get(key, []):
                findings.append(finding)
                reviewed = key == "Misconfigurations" and reviewed_false_positive(
                    result.get("Target", ""), finding, source_root)
                if reviewed:
                    reviews.append(REVIEW_NOTE)
                elif finding["Severity"] in ("HIGH", "CRITICAL"):
                    blocking += 1
    return len(findings), blocking, reviews


def scan_findings(name, data, source_root):
    if name.startswith("trivy"):
        return trivy_findings(data, source_root)
    if name == "bandit.json":
        if data.get("errors"):
            raise ValueError("Bandit could not scan all files")
        findings = data["results"]
        return len(findings), sum(item["issue_severity"] == "HIGH" for item in findings), []
    if not isinstance(data, list):
        raise ValueError("Expected a Gitleaks finding list")
    return len(data), len(data), []


def report_row(name, directory, source_root):
    try:
        data = json.loads((directory / name).read_text())
        count, blocking, reviews = scan_findings(name, data, source_root)
        return f"| {name} | {count} | {blocking} |", blocking > 0, reviews
    except (OSError, ValueError, KeyError, TypeError):
        return f"| {name} | Missing or invalid report | FAIL |", True, []


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
        row, blocked, reviewed = report_row(name, directory, source_root)
        lines.append(row)
        failed |= blocked
        reviews.extend(reviewed)
    lines.extend(["", *reviews, "", "**Result: " + ("FAIL" if failed else "PASS") + "**", ""])
    return "\n".join(lines), failed


def report_directory(value):
    root = Path.cwd().resolve() / "reports"
    directory = Path(value).resolve()
    if not directory.is_relative_to(root):
        raise argparse.ArgumentTypeError("Report directory must be inside this repository's reports/ directory")
    return directory


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["repository", "image"])
    parser.add_argument("directory", type=report_directory)
    args = parser.parse_args()
    summary, failed = summarize(args.mode, args.directory)
    args.directory.mkdir(parents=True, exist_ok=True)
    (args.directory / f"{args.mode}-summary.md").write_text(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
            output.write(summary)
    print(summary)
    raise SystemExit(int(failed))
