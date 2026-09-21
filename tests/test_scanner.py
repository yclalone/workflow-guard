from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from workflow_guard.cli import main
from workflow_guard.models import Finding, ScanResult, Severity
from workflow_guard.report import render_github, render_json, render_sarif
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

    def test_sarif_report_contains_github_code_scanning_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workflow = Path(temp) / "risky.yaml"
            workflow.write_text(INSECURE_WORKFLOW, encoding="utf-8")
            result = scan_path(workflow)
        payload = json.loads(render_sarif(result))
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "workflow-guard")
        self.assertEqual(len(run["results"]), 5)
        critical = next(item for item in run["results"] if item["ruleId"] == "WG006")
        self.assertEqual(critical["level"], "error")
        location = critical["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "risky.yaml")
        self.assertEqual(location["region"]["startLine"], 9)

    def test_github_report_emits_annotations_and_escapes_values(self) -> None:
        result = ScanResult(
            ".",
            1,
            (
                Finding(
                    "WG999",
                    Severity.MEDIUM,
                    "Message 100%\nnext",
                    ".github/workflows/a,b.yml",
                    2,
                    "Review: now",
                ),
            ),
        )
        report = render_github(result)
        self.assertEqual(
            report,
            "::warning file=.github/workflows/a%2Cb.yml,line=2,title=WG999 (medium)::"
            "Message 100%25%0Anext Fix: Review: now\n",
        )

    def test_github_report_keeps_clean_runs_annotation_free(self) -> None:
        report = render_github(ScanResult(".", 2, ()))
        self.assertEqual(report, "workflow-guard: no findings in 2 workflow file(s)\n")

    def test_cli_writes_sarif_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workflow = root / "risky.yml"
            output = root / "results.sarif"
            workflow.write_text(INSECURE_WORKFLOW, encoding="utf-8")
            exit_code = main(
                [str(workflow), "--format", "sarif", "--output", str(output), "--fail-on", "none"]
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "WG002")

    def test_cli_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workflow = Path(temp) / "secure.yml"
            workflow.write_text(SECURE_WORKFLOW, encoding="utf-8")
            self.assertEqual(main([str(workflow), "--fail-on", "high"]), 0)

    def test_cli_can_ignore_a_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workflow = root / "risky.yml"
            output = root / "results.json"
            workflow.write_text(INSECURE_WORKFLOW, encoding="utf-8")
            exit_code = main(
                [
                    str(workflow),
                    "--format",
                    "json",
                    "--output",
                    str(output),
                    "--fail-on",
                    "high",
                    "--ignore-rule",
                    "wg002",
                    "--ignore-rule",
                    "WG006",
                    "--ignore-rule",
                    "WG007",
                ]
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            {item["rule_id"] for item in payload["findings"]},
            {"WG004", "WG005"},
        )

    def test_cli_rejects_unknown_ignored_rule(self) -> None:
        with self.assertRaises(SystemExit) as context:
            main([".", "--ignore-rule", "WG999"])
        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
