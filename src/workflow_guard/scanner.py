"""Workflow discovery and scanning entry points."""

from __future__ import annotations

from pathlib import Path

from .models import Finding, ScanResult, display_path
from .rules import evaluate


WORKFLOW_SUFFIXES = {".yml", ".yaml"}


def discover_workflows(target: Path) -> list[Path]:
    """Discover workflow files from a file, workflow directory, or repository root."""

    target = target.expanduser()
    if target.is_file():
        return [target] if target.suffix.lower() in WORKFLOW_SUFFIXES else []
    if not target.exists():
        raise FileNotFoundError(f"target does not exist: {target}")
    workflow_dir = target
    conventional = target / ".github" / "workflows"
    if conventional.is_dir():
        workflow_dir = conventional
    return sorted(
        path
        for path in workflow_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in WORKFLOW_SUFFIXES
    )


def scan_text(text: str, path: str = "<memory>") -> tuple[Finding, ...]:
    """Scan one workflow represented as text."""

    lines = text.splitlines()
    return tuple(sorted(evaluate(lines, path), key=lambda item: (item.line, item.rule_id)))


def scan_path(target: str | Path) -> ScanResult:
    """Scan a workflow file, directory, or repository root."""

    target_path = Path(target)
    files = discover_workflows(target_path)
    root = target_path if target_path.is_dir() else target_path.parent
    findings: list[Finding] = []
    for workflow in files:
        text = workflow.read_text(encoding="utf-8")
        findings.extend(scan_text(text, display_path(workflow, root)))
    findings.sort(key=lambda item: (item.path, item.line, item.rule_id))
    return ScanResult(str(target_path), len(files), tuple(findings))

