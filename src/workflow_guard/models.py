"""Data models shared by the scanner, reporters, and CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    """Finding severity ordered from least to most important."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError as exc:
            choices = ", ".join(item.name.lower() for item in cls)
            raise ValueError(f"unknown severity {value!r}; choose from {choices}") from exc

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Finding:
    """One actionable issue found in a workflow."""

    rule_id: str
    severity: Severity
    message: str
    path: str
    line: int
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["severity"] = str(self.severity)
        return data


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Findings and scan metadata for one invocation."""

    target: str
    files_scanned: int
    findings: tuple[Finding, ...]

    def at_or_above(self, severity: Severity) -> bool:
        return any(item.severity >= severity for item in self.findings)

    def to_dict(self) -> dict[str, object]:
        counts = {str(level): 0 for level in Severity}
        for finding in self.findings:
            counts[str(finding.severity)] += 1
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "summary": counts,
            "findings": [item.to_dict() for item in self.findings],
        }


def display_path(path: Path, root: Path | None = None) -> str:
    """Return a stable, user-friendly path for reports."""

    if root is not None:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    return path.as_posix()

