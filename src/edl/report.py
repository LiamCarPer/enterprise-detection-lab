"""Human and machine-readable validation reports."""

from __future__ import annotations

import json

from rich.table import Table

from .models import ValidationReport


def render_table(report: ValidationReport) -> Table:
    """Render the validation report as a Rich table."""
    table = Table(title="Validation Report")
    table.add_column("Type")
    table.add_column("Artifact")
    table.add_column("Status")
    table.add_column("Errors", justify="right")
    table.add_column("Warnings", justify="right")
    table.add_column("Path")

    if not report.artifacts:
        table.add_row("—", "—", "—", "0", "0", "—")
    else:
        for artifact in report.artifacts:
            table.add_row(
                artifact.artifact_type,
                artifact.artifact_id or "unknown",
                artifact.status or "unknown",
                str(len(artifact.errors)),
                str(len(artifact.warnings)),
                artifact.path,
            )

    table.caption = (
        f"{report.summary.get('errors', 0)} error(s), "
        f"{report.summary.get('warnings', 0)} warning(s)"
    )
    return table


def render_json(report: ValidationReport) -> str:
    """Render the validation report as stable JSON."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def render_markdown(report: ValidationReport) -> str:
    """Render the validation report as Markdown."""
    lines = [
        "# Validation Report",
        "",
        f"**OK:** {'yes' if report.ok else 'no'}",
        "",
        "## Summary",
        "",
        f"- Detections: {report.summary.get('detections', 0)}",
        f"- Investigations: {report.summary.get('investigations', 0)}",
        f"- Templates: {report.summary.get('templates', 0)}",
        f"- Telemetry sources: {report.summary.get('telemetry_sources', 0)}",
        f"- Errors: {report.summary.get('errors', 0)}",
        f"- Warnings: {report.summary.get('warnings', 0)}",
        "",
    ]

    if report.artifacts:
        lines.extend(
            [
                "## Artifacts",
                "",
                "| Type | Artifact | Status | Errors | Warnings | Path |",
                "|---|---|---|---:|---:|---|",
            ]
        )
        for artifact in report.artifacts:
            lines.append(
                f"| {artifact.artifact_type} | {artifact.artifact_id or 'unknown'} | "
                f"{artifact.status or 'unknown'} | {len(artifact.errors)} | "
                f"{len(artifact.warnings)} | `{artifact.path}` |"
            )
        lines.append("")

    if report.errors:
        lines.extend(["## Errors", ""])
        for issue in report.errors:
            lines.append(f"- `{issue.code}` {issue.message}")
        lines.append("")

    if report.warnings:
        lines.extend(["## Warnings", ""])
        for issue in report.warnings:
            lines.append(f"- `{issue.code}` {issue.message}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
