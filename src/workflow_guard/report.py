"""Human-readable and machine-readable report renderers."""

from __future__ import annotations

import json

from .models import ScanResult, Severity


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


def render(result: ScanResult, output_format: str) -> str:
    if output_format == "text":
        return render_text(result)
    if output_format == "markdown":
        return render_markdown(result)
    if output_format == "json":
        return render_json(result)
    raise ValueError(f"unsupported output format: {output_format}")

