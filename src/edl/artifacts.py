"""Artifact discovery and ID conventions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

ArtifactKind = Literal["detection", "investigation"]

DOMAIN_BY_CODE = {
    "IDN": "identity",
    "END": "endpoint",
    "CLD": "cloud",
    "SAA": "saas",
    "NET": "network",
    "K8S": "kubernetes",
    "AGT": "agent",
}


@dataclass(frozen=True)
class ArtifactRef:
    kind: ArtifactKind
    path: Path
    meta_path: Path


def discover_artifacts(root: Path, include_path: Path | None = None) -> list[ArtifactRef]:
    """Find detection and investigation packages under root."""
    if include_path is not None and include_path.is_file():
        include_path = include_path.parent

    refs: list[ArtifactRef] = []

    for meta_path in sorted((root / "detections").glob("**/meta.yaml")):
        artifact_path = meta_path.parent
        if include_path is not None and not artifact_path.is_relative_to(include_path):
            continue
        refs.append(ArtifactRef("detection", artifact_path, meta_path))

    for meta_path in sorted((root / "investigations").glob("**/meta.yaml")):
        artifact_path = meta_path.parent
        if include_path is not None and not artifact_path.is_relative_to(include_path):
            continue
        refs.append(ArtifactRef("investigation", artifact_path, meta_path))

    return sorted(refs, key=lambda ref: (ref.kind, str(ref.path)))


def expected_domain_from_id(detection_id: str) -> str | None:
    """Return the domain implied by a DET-XXX-NNN ID."""
    parts = detection_id.split("-")
    if len(parts) != 3 or parts[0] != "DET":
        return None
    return DOMAIN_BY_CODE.get(parts[1])


def relative_path(path: Path, root: Path) -> str:
    """Return a repository-relative path when possible."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
