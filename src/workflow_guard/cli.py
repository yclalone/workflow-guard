"""Command-line interface for workflow-guard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .models import ScanResult, Severity
from .report import render
from .rules import RULE_IDS
from .scanner import scan_path


def _rule_id(value: str) -> str:
    rule_id = value.upper()
    if rule_id not in RULE_IDS:
        choices = ", ".join(RULE_IDS)
        raise argparse.ArgumentTypeError(f"unknown rule {value!r}; choose from {choices}")
    return rule_id


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workflow-guard",
        description="Scan GitHub Actions workflows for security and maintainability risks.",
    )
    parser.add_argument("target", nargs="?", default=".", help="workflow file, directory, or repository root")
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "github", "sarif"),
        default="text",
    )
    parser.add_argument("--output", type=Path, help="write the report to this file instead of stdout")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="return exit code 1 when a finding reaches this severity (default: high)",
    )
    parser.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        type=_rule_id,
        metavar="RULE_ID",
        help="ignore a built-in rule; repeat this option to ignore multiple rules",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = scan_path(args.target)
        if args.ignore_rule:
            ignored = set(args.ignore_rule)
            result = ScanResult(
                result.target,
                result.files_scanned,
                tuple(item for item in result.findings if item.rule_id not in ignored),
            )
        report = render(result, args.format)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"workflow-guard: error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report, encoding="utf-8")
        except OSError as exc:
            print(f"workflow-guard: error: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(report)

    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    return 1 if result.at_or_above(threshold) else 0


if __name__ == "__main__":
    raise SystemExit(main())
