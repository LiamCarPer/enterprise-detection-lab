from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 6, "negative": 6, "benign": 5}


def test_query_checks_admin_grant_and_trust_fields() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "entra-audit" in query
    assert "Consent to application" in query
    assert "Add OAuth2PermissionGrant" in query
    assert "Add delegated permission grant" in query
    assert '"consent_type": "admin"' in query
    assert '"consent_type": "tenant"' in query
    assert '"tenant_wide": true' in query
    assert '"approved_app": false' in query
    assert '"publisher_verified": false' in query
    assert '"redirect_uri_trusted": false' in query
    assert '"publisher_reputation": "untrusted"' in query


def test_metadata_declares_detection_identity() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-IDN-005" in meta
    assert "T1528" in meta
    assert "T1098" in meta
    assert "status: tested" in meta


def test_fixtures_are_synthetic_and_complete() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == EXPECTED_FIXTURE_COUNTS[kind]
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "entra-audit" for item in fixtures)


def test_positive_fixtures_have_an_admin_grant_and_failed_trust() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    for item in fixtures:
        event = item["event"]
        target = event["targetResources"][0]
        assert event["result"] == "success"
        assert event["operationName"] in {
            "Consent to application",
            "Add OAuth2PermissionGrant",
            "Add delegated permission grant",
        }
        assert target.get("consentType") in {"Admin", "Tenant"} or target.get("tenantWide") is True
        untrusted = (
            target.get("publisherVerified") is False
            or target.get("redirectUriTrusted") is False
            or target.get("appOwnerOrganizationId") == "44444444-4444-4444-8444-444444444444"
        )
        assert untrusted


def test_approved_application_is_suppressed() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "negative.json").read_text())
    approved = [item for item in fixtures if item["scenario"] == "neg-6"]
    assert len(approved) == 1
    target = approved[0]["event"]["targetResources"][0]
    assert target["appId"] == "00000000-0000-4000-8000-000000009101"
    assert target["redirectUri"] == "https://login.approved.example/callback"
    assert target["publisherVerified"] is False
