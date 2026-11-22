from __future__ import annotations

from pathlib import Path

from edl.artifacts import (
    discover_artifacts,
    expected_domain_from_id,
    relative_path,
)


def _meta(root: Path, relative: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("id: DET-IDN-001\n", encoding="utf-8")
    return path


def test_discover_filters_by_file_and_directory(tmp_path: Path) -> None:
    detection_meta = _meta(tmp_path, "detections/identity/oauth/meta.yaml")
    investigation_meta = _meta(tmp_path, "investigations/01-case/meta.yaml")

    all_refs = discover_artifacts(tmp_path)
    assert {ref.kind for ref in all_refs} == {"detection", "investigation"}

    detection_refs = discover_artifacts(tmp_path, include_path=detection_meta)
    assert len(detection_refs) == 1
    assert detection_refs[0].kind == "detection"

    investigation_refs = discover_artifacts(tmp_path, include_path=investigation_meta.parent)
    assert len(investigation_refs) == 1
    assert investigation_refs[0].kind == "investigation"


def test_expected_domain_from_id() -> None:
    assert expected_domain_from_id("DET-IDN-001") == "identity"
    assert expected_domain_from_id("DET-CLD-002") == "cloud"
    assert expected_domain_from_id("DET-XXX-001") is None
    assert expected_domain_from_id("not-a-detection") is None


def test_relative_path_handles_outside_root(tmp_path: Path) -> None:
    outside = Path("/tmp/outside-artifact")
    assert relative_path(outside, tmp_path) == str(outside)
