"""Conservative, line-oriented checks for GitHub Actions workflow files.

The scanner intentionally avoids a YAML dependency. It only interprets the
small subset of YAML structure needed by the rules below and never rewrites a
workflow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding, Severity


_KEY_RE = re.compile(r"^(?P<indent>\s*)(?P<key>[^#][^:]*):(?:\s*(?P<value>.*))?$")
_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?(?P<value>[^'\"\s#]+)")
_PINNED_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_REMOTE_SCRIPT_RE = re.compile(
    r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _Job:
    name: str
    line: int
    start_index: int
    end_index: int


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _meaningful(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped and not stripped.startswith("#"))


def _top_level_index(lines: list[str], key: str) -> int | None:
    for index, line in enumerate(lines):
        match = _KEY_RE.match(line)
        if match and not match.group("indent") and match.group("key").strip().strip("'\"") == key:
            return index
    return None


def _block_end(lines: list[str], start: int, base_indent: int) -> int:
    for index in range(start + 1, len(lines)):
        if _meaningful(lines[index]) and _indent(lines[index]) <= base_indent:
            return index
    return len(lines)


def _jobs(lines: list[str]) -> list[_Job]:
    jobs_index = _top_level_index(lines, "jobs")
    if jobs_index is None:
        return []
    jobs_end = _block_end(lines, jobs_index, 0)
    starts: list[tuple[str, int]] = []
    for index in range(jobs_index + 1, jobs_end):
        line = lines[index]
        match = _KEY_RE.match(line)
        if not match or len(match.group("indent")) != 2:
            continue
        name = match.group("key").strip().strip("'\"")
        if name:
            starts.append((name, index))
    result: list[_Job] = []
    for position, (name, index) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else jobs_end
        result.append(_Job(name, index + 1, index, end))
    return result


def _has_pull_request_target(lines: list[str]) -> bool:
    on_index = _top_level_index(lines, "on")
    if on_index is None:
        return False
    if "pull_request_target" in lines[on_index].split("#", 1)[0]:
        return True
    end = _block_end(lines, on_index, 0)
    return any("pull_request_target" in line.split("#", 1)[0] for line in lines[on_index + 1 : end])


def _finding(
    rule_id: str,
    severity: Severity,
    message: str,
    path: str,
    line: int,
    recommendation: str,
) -> Finding:
    return Finding(rule_id, severity, message, path, line, recommendation)


def evaluate(lines: list[str], path: str) -> list[Finding]:
    """Evaluate all built-in rules against a workflow's source lines."""

    findings: list[Finding] = []
    permissions_index = _top_level_index(lines, "permissions")

    if permissions_index is None:
        findings.append(
            _finding(
                "WG001",
                Severity.MEDIUM,
                "Workflow does not declare top-level token permissions.",
                path,
                1,
                "Add a least-privilege permissions block, often `permissions: contents: read`.",
            )
        )
    else:
        permission_header = lines[permissions_index].split("#", 1)[0].lower()
        if "write-all" in permission_header:
            findings.append(
                _finding(
                    "WG002",
                    Severity.HIGH,
                    "Workflow grants write access to every available token scope.",
                    path,
                    permissions_index + 1,
                    "Replace `write-all` with only the individual write scopes the workflow requires.",
                )
            )
        permission_end = _block_end(lines, permissions_index, 0)
        for index in range(permissions_index + 1, permission_end):
            match = _KEY_RE.match(lines[index])
            if not match or match.group("value") is None:
                continue
            if match.group("value").split("#", 1)[0].strip().lower() == "write":
                scope = match.group("key").strip()
                findings.append(
                    _finding(
                        "WG003",
                        Severity.MEDIUM,
                        f"Token scope `{scope}` has write access.",
                        path,
                        index + 1,
                        "Confirm this write scope is necessary and move it to the narrowest possible job.",
                    )
                )

    checkout_lines: list[int] = []
    for index, line in enumerate(lines):
        match = _USES_RE.match(line)
        if not match:
            continue
        value = match.group("value")
        if value.startswith("actions/checkout@"):
            checkout_lines.append(index + 1)
        if value.startswith("./") or value.startswith("docker://"):
            continue
        if "@" not in value:
            findings.append(
                _finding(
                    "WG004",
                    Severity.MEDIUM,
                    f"Action `{value}` has no immutable version reference.",
                    path,
                    index + 1,
                    "Pin external actions to a full 40-character commit SHA.",
                )
            )
            continue
        action, ref = value.rsplit("@", 1)
        if not _PINNED_SHA_RE.fullmatch(ref):
            findings.append(
                _finding(
                    "WG004",
                    Severity.MEDIUM,
                    f"Action `{action}` is pinned to mutable ref `{ref}`.",
                    path,
                    index + 1,
                    "Pin external actions to a full 40-character commit SHA and keep the release tag in a comment.",
                )
            )

    for job in _jobs(lines):
        has_timeout = any(
            _indent(lines[index]) == 4 and lines[index].lstrip().startswith("timeout-minutes:")
            for index in range(job.start_index + 1, job.end_index)
        )
        if not has_timeout:
            findings.append(
                _finding(
                    "WG005",
                    Severity.LOW,
                    f"Job `{job.name}` has no execution timeout.",
                    path,
                    job.line,
                    "Add `timeout-minutes` to prevent stalled jobs from consuming runner time indefinitely.",
                )
            )

    if _has_pull_request_target(lines) and checkout_lines:
        findings.append(
            _finding(
                "WG006",
                Severity.CRITICAL,
                "`pull_request_target` is combined with repository checkout.",
                path,
                checkout_lines[0],
                "Avoid checking out or executing pull-request code in a privileged `pull_request_target` workflow.",
            )
        )

    for index, line in enumerate(lines):
        if _REMOTE_SCRIPT_RE.search(line):
            findings.append(
                _finding(
                    "WG007",
                    Severity.HIGH,
                    "Remote content is piped directly into a shell.",
                    path,
                    index + 1,
                    "Download the script, verify an expected checksum, then execute the verified local file.",
                )
            )

    return findings
