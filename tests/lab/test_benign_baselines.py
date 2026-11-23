from __future__ import annotations

from pathlib import Path

import pytest

from edl import config
from edl.detection import run_baseline
from edl.ingest import OpenSearchClient

pytestmark = pytest.mark.lab

BASELINE_DIR = config.ROOT / "lab" / "datasets" / "synthetic" / "benign-baseline"
CASES = (
    ("DET-IDN-001", BASELINE_DIR / "identity-signin.json"),
    ("DET-IDN-002", BASELINE_DIR / "identity-audit.json"),
    ("DET-CLD-001", BASELINE_DIR / "cloudtrail.json"),
    ("DET-CLD-002", BASELINE_DIR / "cloudtrail.json"),
)


@pytest.mark.parametrize(("detection_id", "dataset"), CASES, ids=lambda item: str(item))
def test_detection_has_no_benign_baseline_matches(detection_id: str, dataset: Path) -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            detection_id,
            dataset,
            client=client,
            latency_runs=1,
        )
        assert result.sample_size == 20
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()
