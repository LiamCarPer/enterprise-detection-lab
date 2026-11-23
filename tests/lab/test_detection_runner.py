from __future__ import annotations

import pytest

from edl import config
from edl.detection import run_detection
from edl.ingest import OpenSearchClient

pytestmark = pytest.mark.lab

TEMPLATE = config.ROOT / "detections" / "endpoint" / "_template"


def test_reference_detection_executes_and_cleans_up() -> None:
    client = OpenSearchClient()
    try:
        result = run_detection(
            TEMPLATE,
            client=client,
            latency_runs=3,
        )
        assert result.passed
        assert result.sample_size == 3
        assert result.true_positives == 1
        assert result.false_negatives == 0
        assert result.false_positives == 0
        assert result.true_negatives == 2
        assert client.count("edl-events-detect-*") == 0
    finally:
        client.close()


def test_risky_signin_detection_executes() -> None:
    client = OpenSearchClient()
    try:
        result = run_detection(
            config.ROOT / "detections" / "identity" / "risky-signin-single-factor",
            client=client,
            latency_runs=3,
        )
        assert result.passed
        assert result.sample_size == 15
        assert result.true_positives == 5
        assert result.false_negatives == 0
        assert result.false_positives == 0
        assert result.true_negatives == 10
        assert client.count("edl-events-detect-*") == 0
    finally:
        client.close()
