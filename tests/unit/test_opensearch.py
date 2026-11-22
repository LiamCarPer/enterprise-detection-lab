from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from edl.errors import IngestError
from edl.ingest import OpenSearchClient

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler) -> OpenSearchClient:
    return OpenSearchClient(
        "http://opensearch.test",
        transport=httpx.MockTransport(handler),
    )


def test_bulk_sends_ndjson_with_ids_and_refresh() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"errors": False, "items": []})

    client = _client(handler)
    try:
        client.bulk(
            "edl-events-entra-signin-2026.11.01",
            [("doc-1", {"source": "entra-signin", "user": "analyst@example.test"})],
            refresh=True,
        )
    finally:
        client.close()

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert request.url.path == "/edl-events-entra-signin-2026.11.01/_bulk"
    assert request.url.params["refresh"] == "true"
    lines = request.content.decode("utf-8").splitlines()
    assert json.loads(lines[0]) == {"index": {"_id": "doc-1"}}
    assert json.loads(lines[1])["user"] == "analyst@example.test"


def test_bulk_without_actions_does_not_call_opensearch() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("unexpected request")

    client = _client(handler)
    try:
        client.bulk("edl-events-test", [], refresh=False)
    finally:
        client.close()


def test_bulk_reports_http_error() -> None:
    client = _client(lambda _request: httpx.Response(503, text="unavailable"))
    with pytest.raises(IngestError, match="HTTP 503"):
        client.bulk("edl-events-test", [("doc-1", {})], refresh=True)


def test_bulk_reports_connection_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = _client(handler)
    with pytest.raises(IngestError, match="Could not reach OpenSearch"):
        client.bulk("edl-events-test", [("doc-1", {})], refresh=True)


def test_bulk_reports_non_json() -> None:
    client = _client(lambda _request: httpx.Response(200, text="not-json"))
    with pytest.raises(IngestError, match="non-JSON"):
        client.bulk("edl-events-test", [("doc-1", {})], refresh=True)


def test_bulk_reports_non_object() -> None:
    client = _client(lambda _request: httpx.Response(200, json=[1, 2]))
    with pytest.raises(IngestError, match="non-object"):
        client.bulk("edl-events-test", [("doc-1", {})], refresh=True)


def test_bulk_reports_item_failure() -> None:
    payload = {
        "errors": True,
        "items": [
            {
                "index": {
                    "status": 400,
                    "error": {"type": "mapper_parsing_exception"},
                }
            }
        ],
    }
    client = _client(lambda _request: httpx.Response(200, json=payload))
    with pytest.raises(IngestError, match="mapper_parsing_exception"):
        client.bulk("edl-events-test", [("doc-1", {})], refresh=True)


def test_bulk_reports_unknown_item_failure() -> None:
    payload = {"errors": True, "items": [1]}
    client = _client(lambda _request: httpx.Response(200, json=payload))
    with pytest.raises(IngestError, match="unknown bulk error"):
        client.bulk("edl-events-test", [("doc-1", {})], refresh=True)


def test_count_reads_integer() -> None:
    client = _client(lambda _request: httpx.Response(200, json={"count": 4}))
    assert client.count("edl-events-test") == 4


def test_count_returns_zero_for_missing_index() -> None:
    client = _client(lambda _request: httpx.Response(404))
    assert client.count("edl-events-test") == 0


def test_count_reports_http_error() -> None:
    client = _client(lambda _request: httpx.Response(500, text="broken"))
    with pytest.raises(IngestError, match="HTTP 500"):
        client.count("edl-events-test")


def test_count_reports_connection_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    client = _client(handler)
    with pytest.raises(IngestError, match="Could not reach OpenSearch"):
        client.count("edl-events-test")


def test_count_reports_non_json() -> None:
    client = _client(lambda _request: httpx.Response(200, text="not-json"))
    with pytest.raises(IngestError, match="non-JSON"):
        client.count("edl-events-test")


@pytest.mark.parametrize("payload", [[], {}, {"count": "4"}])
def test_count_rejects_missing_integer(payload: object) -> None:
    client = _client(lambda _request: httpx.Response(200, json=payload))
    with pytest.raises(IngestError, match="integer count"):
        client.count("edl-events-test")


def test_delete_matching_succeeds() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"acknowledged": True})

    client = _client(handler)
    client.delete_matching("edl-events-test-*")
    assert requests[0].method == "DELETE"
    assert requests[0].url.path == "/edl-events-test-*"


def test_delete_matching_ignores_missing_index() -> None:
    client = _client(lambda _request: httpx.Response(404))
    client.delete_matching("edl-events-test-*")


def test_delete_matching_reports_http_error() -> None:
    client = _client(lambda _request: httpx.Response(500, text="broken"))
    with pytest.raises(IngestError, match="HTTP 500"):
        client.delete_matching("edl-events-test-*")


def test_delete_matching_reports_connection_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = _client(handler)
    with pytest.raises(IngestError, match="Could not reach OpenSearch"):
        client.delete_matching("edl-events-test-*")


def test_context_manager_closes_client() -> None:
    client = OpenSearchClient("http://opensearch.test")
    with client as active:
        assert active is client
    assert client._client.is_closed
