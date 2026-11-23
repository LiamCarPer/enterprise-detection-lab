from __future__ import annotations

from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]


def test_reference_artifact_has_fixtures() -> None:
    for kind in ("positive", "negative", "benign"):
        assert (PACKAGE / "fixtures" / f"{kind}.json").exists()
