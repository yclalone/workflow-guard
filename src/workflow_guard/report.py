"""Human-readable and machine-readable report renderers."""

from __future__ import annotations

import json

from . import __version__
from .models import ScanResult, Severity


_SARIF_LEVELS = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def render_text(result: ScanResult) -> str:
    lines = [
        f"workflow-guard: scanned {result.files_scanned} workflow file(s)",
        f"findings: {len(result.findings)}",
    ]
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    for item in result.findings:
        lines.extend(
            [
                "",
                f"[{item.severity.name}] {item.rule_id} {item.path}:{item.line}",
                item.message,
                f"Fix: {item.recommendation}",
            ]
        )
    return "\n".join(lines) + "\n"


def render_markdown(result: ScanResult) -> str:
    counts = {str(level): 0 for level in Severity}
    for item in result.findings:
        counts[str(item.severity)] += 1
    lines = [
        "# workflow-guard report",
        "",
        f"Scanned **{result.files_scanned}** workflow file(s) and found **{len(result.findings)}** issue(s).",
        "",
        "| Critical | High | Medium | Low |",
        "| ---: | ---: | ---: | ---: |",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
    ]
    if not result.findings:
        lines.extend(["", "No findings."])
    else:
        lines.extend(["", "## Findings"])
        for item in result.findings:
            lines.extend(
                [
                    "",
                    f"### {item.rule_id}: {item.message}",
                    "",
                    f"- Severity: **{item.severity}**",
                    f"- Location: `{item.path}:{item.line}`",
                    f"- Recommendation: {item.recommendation}",
                ]
            )
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    """Render findings as SARIF 2.1.0 for GitHub code scanning."""

    rules: dict[str, dict[str, object]] = {}
    sarif_results: list[dict[str, object]] = []
    for item in result.findings:
        level = _SARIF_LEVELS[item.severity]
        rules.setdefault(
            item.rule_id,
            {
                "id": item.rule_id,
                "shortDescription": {"text": item.message},
                "help": {"text": item.recommendation},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": ["security", "github-actions"],
                    "severity": str(item.severity),
                },
            },
        )
        sarif_results.append(
            {
                "ruleId": item.rule_id,
                "level": level,
                "message": {"text": item.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": item.path.replace("\\", "/"),
                            },
                            "region": {"startLine": max(1, item.line)},
                        }
                    }
                ],
                "properties": {
                    "recommendation": item.recommendation,
                    "severity": str(item.severity),
                },
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "workflow-guard",
                        "version": __version__,
                        "informationUri": "https://github.com/yclalone/workflow-guard",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render(result: ScanResult, output_format: str) -> str:
    if output_format == "text":
        return render_text(result)
    if output_format == "markdown":
        return render_markdown(result)
    if output_format == "json":
        return render_json(result)
    if output_format == "sarif":
        return render_sarif(result)
    raise ValueError(f"unsupported output format: {output_format}")
