from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_targets_privileged_pod_creation() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    for field in ("source", "event_class", "action", "resource_name", "result", "privileged"):
        assert field in query
    assert "kubernetes-audit" in query
    assert "pods" in query


def test_fixtures_are_synthetic_and_complete() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 5
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "kubernetes-audit" for item in fixtures)


def test_positive_fixtures_contain_privileged_containers() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    for item in fixtures:
        spec = item["event"]["requestObject"]["spec"]
        containers = spec.get("containers", []) + spec.get("initContainers", [])
        assert any(
            container.get("securityContext", {}).get("privileged") is True
            for container in containers
        )


def test_metadata_declares_the_kubernetes_source() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-K8S-001" in meta
    assert "source: kubernetes-audit" in meta
    assert "T1611" in meta
