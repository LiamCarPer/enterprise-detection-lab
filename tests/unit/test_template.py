from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from edl.errors import ValidationError
from edl.template import TEMPLATE_DETECTION, new_detection, new_investigation


def test_new_detection_scaffolds_valid_artifact(tmp_path: Path) -> None:
    target = new_detection(
        domain="identity",
        slug="oauth-consent",
        detection_id="DET-IDN-001",
        title="OAuth consent grant",
        root=tmp_path,
    )
    assert target.exists()
    assert (target / "meta.yaml").exists()
    assert (target / "queries" / "opensearch.json").exists()
    assert "DET-IDN-001" in (target / "meta.yaml").read_text()
    assert "OAuth consent grant" in (target / "rule.sigma.yml").read_text()


def test_new_detection_dry_run_does_not_write(tmp_path: Path) -> None:
    target = new_detection(
        domain="identity",
        slug="oauth-consent",
        detection_id="DET-IDN-001",
        title="OAuth consent grant",
        root=tmp_path,
        dry_run=True,
    )
    assert not target.exists()


def test_new_detection_rejects_domain_mismatch(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="implies domain"):
        new_detection(
            domain="identity",
            slug="oauth-consent",
            detection_id="DET-CLD-001",
            title="OAuth consent grant",
            root=tmp_path,
        )


def test_new_detection_rejects_existing_target(tmp_path: Path) -> None:
    target = tmp_path / "detections" / "identity" / "oauth-consent"
    target.mkdir(parents=True)
    with pytest.raises(ValidationError, match="already exists"):
        new_detection(
            domain="identity",
            slug="oauth-consent",
            detection_id="DET-IDN-001",
            title="OAuth consent grant",
            root=tmp_path,
        )


def test_new_investigation_scaffolds_valid_artifact(tmp_path: Path) -> None:
    template_detection = tmp_path / "detections" / "endpoint" / "_template"
    template_detection.parent.mkdir(parents=True)
    shutil.copytree(TEMPLATE_DETECTION, template_detection)

    target = new_investigation(
        slug="identity-to-cloud",
        investigation_id="INV-001",
        title="Identity to cloud",
        root=tmp_path,
    )
    assert target.exists()
    assert (target / "meta.yaml").exists()
    assert "INV-001" in (target / "meta.yaml").read_text()
    assert "Identity to cloud" in (target / "README.md").read_text()


def test_new_investigation_dry_run_does_not_write(tmp_path: Path) -> None:
    target = new_investigation(
        slug="identity-to-cloud",
        investigation_id="INV-001",
        title="Identity to cloud",
        root=tmp_path,
        dry_run=True,
    )
    assert not target.exists()
