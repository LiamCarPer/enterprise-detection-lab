"""Typed validation report models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Severity = Literal["error", "warning"]
ArtifactType = Literal["detection", "investigation", "telemetry-source"]
IssueType = Literal["detection", "investigation", "telemetry-source", "repository"]


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    severity: Severity
    artifact_type: IssueType
    artifact_id: str
    path: str


@dataclass
class ArtifactResult:
    artifact_type: ArtifactType
    artifact_id: str
    path: str
    status: str
    issues: list[Issue] = field(default_factory=list)

    @property
    def errors(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.artifact_type,
            "id": self.artifact_id,
            "path": self.path,
            "status": self.status,
            "errors": [issue.message for issue in self.errors],
            "warnings": [issue.message for issue in self.warnings],
        }


@dataclass
class ValidationReport:
    artifacts: list[ArtifactResult] = field(default_factory=list)
    global_issues: list[Issue] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    @property
    def issues(self) -> list[Issue]:
        collected = list(self.global_issues)
        for artifact in self.artifacts:
            collected.extend(artifact.issues)
        return collected

    @property
    def errors(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def promote_warnings(self) -> None:
        """Treat every warning as an error for --strict."""
        self.global_issues = [_promote(issue) for issue in self.global_issues]
        for artifact in self.artifacts:
            artifact.issues = [_promote(issue) for issue in artifact.issues]
        self.recompute_summary()

    def recompute_summary(self) -> None:
        def is_template(artifact: ArtifactResult) -> bool:
            return "_template" in Path(artifact.path).parts

        self.summary = {
            "detections": sum(
                artifact.artifact_type == "detection" and not is_template(artifact)
                for artifact in self.artifacts
            ),
            "investigations": sum(
                artifact.artifact_type == "investigation" and not is_template(artifact)
                for artifact in self.artifacts
            ),
            "templates": sum(is_template(artifact) for artifact in self.artifacts),
            "telemetry_sources": sum(
                artifact.artifact_type == "telemetry-source" for artifact in self.artifacts
            ),
            "errors": len(self.errors),
            "warnings": len(self.warnings),
        }

    def to_dict(self) -> dict[str, Any]:
        if not self.summary:
            self.recompute_summary()
        return {
            "ok": self.ok,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "errors": [issue.message for issue in self.errors],
            "warnings": [issue.message for issue in self.warnings],
            "summary": self.summary,
        }


def _promote(issue: Issue) -> Issue:
    if issue.severity != "warning":
        return issue
    return Issue(
        code=issue.code,
        message=issue.message,
        severity="error",
        artifact_type=issue.artifact_type,
        artifact_id=issue.artifact_id,
        path=issue.path,
    )
