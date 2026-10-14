"""Ensure CI fails closed and preserves visibility of lower-severity findings."""
import json
import argparse
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

report_helpers = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                                   "scripts/security-report.py"))
summarize = report_helpers["summarize"]


class SecurityReportTests(unittest.TestCase):
    def test_cli_rejects_report_path_escape_and_symlinks(self):
        validate = report_helpers['report_directory']
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'reports').mkdir()
            (root / 'reports/link').symlink_to(root, target_is_directory=True)
            with patch.object(Path, 'cwd', return_value=root):
                self.assertEqual(validate(str(root / 'reports/image')), root / 'reports/image')
                for path in (root / 'outside', root / 'reports/../outside', root / 'reports/link/outside'):
                    argument = str(path)
                    with self.subTest(path=argument), self.assertRaises(argparse.ArgumentTypeError):
                        validate(argument)
                (root / 'reports/link').unlink()
                (root / 'reports').rmdir()
                (root / 'reports').symlink_to(root / 'outside', target_is_directory=True)
                argument = str(root / 'reports/file')
                with self.assertRaises(argparse.ArgumentTypeError):
                    validate(argument)

    def test_high_without_fix_blocks_and_medium_is_visible(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            report = directory / "trivy-image.json"
            report.write_text(json.dumps({"Results": [{"Vulnerabilities": [
                {"Severity": "HIGH", "FixedVersion": ""}, {"Severity": "MEDIUM"}]}]}))
            summary, failed = summarize("image", directory)
            self.assertTrue(failed)
            self.assertIn("| trivy-image.json | 2 | 1 |", summary)
            report.write_text(json.dumps({"Results": [{"Vulnerabilities": [{"Severity": "MEDIUM"}]}]}))
            summary, failed = summarize("image", directory)
            self.assertFalse(failed)
            self.assertIn("| trivy-image.json | 1 | 0 |", summary)

    def test_missing_and_malformed_reports_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            self.assertTrue(summarize("image", directory)[1])
            (directory / "trivy-image.json").write_text("not JSON")
            self.assertTrue(summarize("image", directory)[1])

    def test_secret_blocks_without_repeating_value(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            (directory / "bandit.json").write_text('{"results": [], "errors": []}')
            (directory / "trivy-fs.json").write_text('{"Results": []}')
            (directory / "gitleaks-dir.json").write_text('[{"Secret": "synthetic-secret"}]')
            (directory / "gitleaks-git.json").write_text('[]')
            summary, failed = summarize("repository", directory)
            self.assertTrue(failed)
            self.assertNotIn("synthetic-secret", summary)
            self.assertIn("| gitleaks-dir.json | 1 | 1 |", summary)

    def test_bandit_analysis_errors_block(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            (directory / "bandit.json").write_text('{"results": [], "errors": [{"reason": "parse error"}]}')
            (directory / "trivy-fs.json").write_text('{"Results": []}')
            (directory / "gitleaks-dir.json").write_text('[]')
            (directory / "gitleaks-git.json").write_text('[]')
            summary, failed = summarize("repository", directory)
            self.assertTrue(failed)
            self.assertIn("| bandit.json | Missing or invalid report | FAIL |", summary)

    def test_only_exact_boolean_configmap_false_positive_is_nonblocking(self):
        finding = {"ID": "KSV-0109", "Severity": "HIGH", "Message":
            "ConfigMap 'checkmarx-mock-source' in 'checkmarx-mock' namespace stores secrets in key(s) or value(s) "
            "'{\"      automountServiceAccountToken\"}'"}
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            report = directory / "trivy-image.json"
            source = directory / 'api-mock/k8s/cli-smoke.yaml'
            source.parent.mkdir(parents=True)
            source.write_text('      automountServiceAccountToken: false\n')
            for target, message, blocked in [
                ('api-mock/k8s/cli-smoke.yaml', finding['Message'], False),
                ('another.yaml', finding['Message'], True),
                ('api-mock/k8s/cli-smoke.yaml', finding['Message'] + ', password', True),
            ]:
                item = dict(finding, Message=message)
                report.write_text(json.dumps({'Results': [{'Target': target,
                    'Misconfigurations': [item]}]}))
                summary, failed = summarize('image', directory, source_root=directory)
                self.assertEqual(failed, blocked)
                if not blocked:
                    self.assertIn('The original finding remains in the JSON report.', summary)
                    self.assertIn('| trivy-image.json | 1 | 0 |', summary)
            report.write_text(json.dumps({'Results': [{'Target': 'api-mock/k8s/cli-smoke.yaml',
                'Misconfigurations': [finding]}]}))
            source.write_text('      automountServiceAccountToken: credential-value\n')
            self.assertTrue(summarize('image', directory, source_root=directory)[1])
