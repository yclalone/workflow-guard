from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from workflow_guard.cli import main
from workflow_guard.report import render_json
from workflow_guard.scanner import scan_path, scan_text


SECURE_WORKFLOW = """\
name: CI
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: python -m unittest
"""


INSECURE_WORKFLOW = """\
name: Risky
on:
  pull_request_target:
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl https://example.invalid/install.sh | bash
"""


class ScannerTests(unittest.TestCase):
    def test_secure_workflow_has_no_findings(self) -> None:
        self.assertEqual(scan_text(SECURE_WORKFLOW, "secure.yml"), ())

    def test_insecure_workflow_reports_expected_rules(self) -> None:
        findings = scan_text(INSECURE_WORKFLOW, "risky.yml")
        self.assertEqual(
            {item.rule_id for item in findings},
            {"WG002", "WG004", "WG005", "WG006", "WG007"},
        )
        checkout = next(item for item in findings if item.rule_id == "WG004")
        self.assertEqual(checkout.line, 9)

    def test_missing_permissions_is_reported(self) -> None:
        findings = scan_text("name: x\non: push\njobs: {}\n", "x.yml")
        self.assertEqual([item.rule_id for item in findings], ["WG001"])

    def test_repository_root_discovers_only_workflows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "ci.yml").write_text(SECURE_WORKFLOW, encoding="utf-8")
            (root / "config.yml").write_text(INSECURE_WORKFLOW, encoding="utf-8")
            result = scan_path(root)
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(result.findings, ())

    def test_json_report_is_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workflow = Path(temp) / "risky.yaml"
            workflow.write_text(INSECURE_WORKFLOW, encoding="utf-8")
            result = scan_path(workflow)
        payload = json.loads(render_json(result))
        self.assertEqual(payload["files_scanned"], 1)
        self.assertEqual(payload["summary"]["critical"], 1)

    def test_cli_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workflow = Path(temp) / "secure.yml"
            workflow.write_text(SECURE_WORKFLOW, encoding="utf-8")
            self.assertEqual(main([str(workflow), "--fail-on", "high"]), 0)


if __name__ == "__main__":
    unittest.main()

