from __future__ import annotations

from pathlib import Path

import pytest

from edl import config
from edl.detection import run_baseline
from edl.ingest import OpenSearchClient

pytestmark = pytest.mark.lab

DATASET = config.ROOT / "lab" / "datasets" / "synthetic" / "benign-baseline" / "endpoint.json"


def test_endpoint_baseline_before_and_after_tuning() -> None:
    client = OpenSearchClient()
    try:
        before = run_baseline(
            "DET-END-001",
            DATASET,
            client=client,
            query_path=Path("queries/opensearch-before.json"),
            latency_runs=1,
        )
        assert before.sample_size == 20
        assert before.matched_count == 8
        assert before.false_positive_rate == 0.4

        after = run_baseline(
            "DET-END-001",
            DATASET,
            client=client,
            latency_runs=1,
        )
        assert after.sample_size == 20
        assert after.matched_count == 0
        assert after.false_positive_rate == 0.0
    finally:
        client.close()


SAAS_DATASET = (
    config.ROOT / "lab" / "datasets" / "synthetic" / "benign-baseline" / "m365-forwarding.json"
)


def test_saas_forwarding_before_and_after_tuning() -> None:
    client = OpenSearchClient()
    try:
        before = run_baseline(
            "DET-SAA-001",
            SAAS_DATASET,
            client=client,
            query_path=Path("queries/opensearch-before.json"),
            latency_runs=1,
        )
        assert before.sample_size == 20
        assert before.matched_count == 8
        assert before.false_positive_rate == 0.4

        after = run_baseline(
            "DET-SAA-001",
            SAAS_DATASET,
            client=client,
            latency_runs=1,
        )
        assert after.sample_size == 20
        assert after.matched_count == 0
        assert after.false_positive_rate == 0.0
    finally:
        client.close()
