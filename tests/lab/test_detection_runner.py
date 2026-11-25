from __future__ import annotations

import pytest

from edl import config
from edl.detection import run_detection, run_detections
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


def test_all_detections_execute() -> None:
    client = OpenSearchClient()
    try:
        results = run_detections(
            config.ROOT,
            include_templates=True,
            client=client,
            latency_runs=2,
        )
        assert {result.detection_id for result in results} == {
            "DET-END-000",
            "DET-IDN-001",
            "DET-IDN-002",
            "DET-IDN-003",
            "DET-END-001",
            "DET-END-002",
            "DET-CLD-001",
            "DET-CLD-002",
            "DET-SAA-001",
            "DET-SAA-002",
            "DET-NET-001",
            "DET-NET-002",
            "DET-K8S-001",
            "DET-K8S-002",
            "DET-SAA-003",
            "DET-SAA-004",
            "DET-SAA-005",
            "DET-SAA-006",
            "DET-SAA-007",
            "DET-SAA-008",
        }
        assert all(result.passed for result in results)
        assert client.count("edl-events-detect-*") == 0
    finally:
        client.close()
