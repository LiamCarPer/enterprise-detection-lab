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
    ("DET-SAA-001", BASELINE_DIR / "m365-audit.json"),
    ("DET-SAA-001", BASELINE_DIR / "m365-forwarding.json"),
    ("DET-SAA-002", BASELINE_DIR / "github-audit.json"),
    ("DET-NET-001", BASELINE_DIR / "zeek-dns.json"),
    ("DET-NET-002", BASELINE_DIR / "suricata-alerts.json"),
    ("DET-K8S-001", BASELINE_DIR / "kubernetes-audit.json"),
    ("DET-K8S-002", BASELINE_DIR / "falco.json"),
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


def test_identity_anomalous_token_mail_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-IDN-008",
            BASELINE_DIR / "identity-anomalous-token-mail.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 8
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_identity_impossible_travel_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-IDN-007",
            BASELINE_DIR / "identity-impossible-travel.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 6
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_identity_session_replay_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-IDN-006",
            BASELINE_DIR / "identity-session-replay.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 6
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_identity_oauth_admin_consent_has_no_benign_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-IDN-005",
            BASELINE_DIR / "identity-oauth-admin-consent.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "event"
        assert result.sample_size == 21
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_identity_oauth_consent_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-IDN-004",
            BASELINE_DIR / "identity-oauth-consent.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 7
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_identity_saas_forwarding_chain_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-SAA-006",
            BASELINE_DIR / "identity-saas-forwarding-chain.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 6
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_forwarding_delivery_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-SAA-007",
            BASELINE_DIR / "forwarding-delivery.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 8
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_external_delivery_dlp_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-SAA-008",
            BASELINE_DIR / "external-delivery-dlp.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 6
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_denied_exception_delivery_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-SAA-009",
            BASELINE_DIR / "denied-exception-delivery.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 10
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_identity_saas_mail_access_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-SAA-005",
            BASELINE_DIR / "identity-saas-mail-access.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 7
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_identity_saas_delegation_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-SAA-004",
            BASELINE_DIR / "identity-saas-delegation.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 10
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_identity_saas_correlation_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-SAA-003",
            BASELINE_DIR / "identity-saas-correlation.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 6
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()


def test_correlation_detection_has_no_benign_sequence_matches() -> None:
    client = OpenSearchClient()
    try:
        result = run_baseline(
            "DET-IDN-003",
            BASELINE_DIR / "identity-correlation.json",
            client=client,
            latency_runs=1,
        )
        assert result.evaluation_unit == "scenario"
        assert result.sample_size == 6
        assert result.matched_count == 0
        assert result.false_positive_rate == 0.0
    finally:
        client.close()
