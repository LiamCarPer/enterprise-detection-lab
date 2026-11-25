from __future__ import annotations

from pathlib import Path

import pytest

from edl import config
from edl.detection import run_detections
from edl.ingest import OpenSearchClient
from edl.loader import load_json, load_mapping
from edl.utils import sha256_file

pytestmark = pytest.mark.lab

INVESTIGATIONS = (
    config.ROOT / "investigations" / "01-identity-to-cloud",
    config.ROOT / "investigations" / "02-endpoint-to-cloud",
    config.ROOT / "investigations" / "03-saas-mailbox-takeover",
)
EXPECTED_DETECTIONS = {
    "INV-001": {
        "DET-IDN-001",
        "DET-IDN-002",
        "DET-CLD-001",
        "DET-CLD-002",
    },
    "INV-002": {
        "DET-END-001",
        "DET-CLD-001",
        "DET-CLD-002",
    },
    "INV-003": {
        "DET-SAA-001",
        "DET-SAA-003",
        "DET-SAA-005",
        "DET-SAA-006",
    },
}


@pytest.mark.parametrize("path", INVESTIGATIONS, ids=lambda item: item.name)
def test_investigation_evidence_query_and_detections(path: Path) -> None:
    meta = load_mapping(path / "meta.yaml")
    investigation_id = str(meta["id"])

    evidence_ids = set()
    for evidence in meta["evidence"]:
        evidence_path = path / evidence["path"]
        assert evidence_path.is_file()
        evidence_ids.add(str(evidence["id"]))
        if "sha256" in evidence:
            assert sha256_file(evidence_path) == evidence["sha256"]

    timeline_ids = {str(item["evidence_id"]) for item in meta["timeline"] if "evidence_id" in item}
    assert timeline_ids <= evidence_ids

    query = load_json(path / "queries" / "opensearch.json")
    linked_detections = set(meta["detections"])
    assert linked_detections == EXPECTED_DETECTIONS[investigation_id]

    client = OpenSearchClient()
    try:
        payload = client.search("edl-events-*", query)
        hits = payload.get("hits", {}).get("hits", [])
        assert isinstance(hits, list)
        assert len(hits) >= len(meta["evidence"])

        for detection_id in sorted(linked_detections):
            results = run_detections(
                config.ROOT,
                detection_id=detection_id,
                client=client,
                latency_runs=1,
            )
            assert results
            assert all(result.passed for result in results), detection_id
    finally:
        client.close()
