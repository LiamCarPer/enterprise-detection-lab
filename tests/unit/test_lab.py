from __future__ import annotations

import subprocess
from pathlib import Path

import duckdb
import httpx
import pytest

from edl import lab
from edl.errors import LabError
from edl.lab import ServiceStatus, compose_command
from edl.utils import split_kusto_commands, split_sql


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        payload: object | None = None,
        *,
        text: str = "",
        invalid_json: bool = False,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self._invalid_json = invalid_json

    def json(self) -> object:
        if self._invalid_json:
            raise ValueError("invalid JSON")
        return self._payload


def test_compose_command_uses_repository_compose_file() -> None:
    command = compose_command("up", "-d")
    assert command[:3] == ["docker", "compose", "-f"]
    assert command[-2:] == ["up", "-d"]
    assert command[3] == str(lab.config.COMPOSE_FILE)


def test_split_kusto_commands_uses_blank_lines() -> None:
    text = """.create-merge table One (TimeGenerated:datetime)

.create-merge table Two (TimeGenerated:datetime)

// comment
.create-merge table Three (TimeGenerated:datetime)
"""
    commands = split_kusto_commands(text)
    assert commands == [
        ".create-merge table One (TimeGenerated:datetime)",
        ".create-merge table Two (TimeGenerated:datetime)",
        ".create-merge table Three (TimeGenerated:datetime)",
    ]


def test_split_sql_ignores_empty_statements() -> None:
    assert split_sql("CREATE TABLE a (x INT);\n\nCREATE TABLE b (y INT);") == [
        "CREATE TABLE a (x INT)",
        "CREATE TABLE b (y INT)",
    ]


def test_compose_command_uses_repository_compose_file_with_args() -> None:
    command = lab.compose_command("up", "-d")
    assert command[:4] == ["docker", "compose", "-f", str(lab.config.COMPOSE_FILE)]
    assert command[4:] == ["up", "-d"]


def test_compose_passes_capture_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(lab, "run", fake_run)
    lab.compose("ps", capture=True)
    assert captured["command"] == lab.compose_command("ps")
    assert captured["capture"] is True


def test_up_down_reset_and_logs_order_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []

    def fake_compose(*args: str, **_: object) -> None:
        calls.append(("compose", args))

    monkeypatch.setattr(lab, "compose", fake_compose)
    monkeypatch.setattr(lab, "wait", lambda: calls.append(("wait", ())))

    lab.up()
    lab.down()
    lab.reset()
    lab.logs()
    lab.logs("opensearch", follow=False)

    assert calls == [
        ("compose", ("up", "-d")),
        ("wait", ()),
        ("compose", ("down",)),
        ("compose", ("down", "-v")),
        ("compose", ("logs", "-f")),
        ("compose", ("logs", "opensearch")),
    ]


def test_opensearch_status_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        lab.httpx,
        "get",
        lambda *_args, **_kwargs: FakeResponse(payload={"status": "yellow"}),
    )
    status = lab._opensearch_status()
    assert status.healthy
    assert status.detail == "yellow"


def test_opensearch_status_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lab.httpx, "get", lambda *_args, **_kwargs: FakeResponse(status_code=503))
    status = lab._opensearch_status()
    assert not status.healthy
    assert status.detail == "HTTP 503"


def test_opensearch_status_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        lab.httpx,
        "get",
        lambda *_args, **_kwargs: FakeResponse(invalid_json=True),
    )
    status = lab._opensearch_status()
    assert not status.healthy


def test_opensearch_status_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(lab.httpx, "get", fail)
    status = lab._opensearch_status()
    assert not status.healthy
    assert "refused" in status.detail


def test_dashboards_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lab.httpx, "get", lambda *_args, **_kwargs: FakeResponse())
    assert lab._dashboards_status().healthy

    monkeypatch.setattr(lab.httpx, "get", lambda *_args, **_kwargs: FakeResponse(status_code=404))
    assert not lab._dashboards_status().healthy

    def fail(*_args: object, **_kwargs: object) -> None:
        raise httpx.ReadTimeout("slow")

    monkeypatch.setattr(lab.httpx, "get", fail)
    assert not lab._dashboards_status().healthy


def test_kusto_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lab.httpx, "post", lambda *_args, **_kwargs: FakeResponse())
    assert lab._kusto_status().healthy

    monkeypatch.setattr(lab.httpx, "post", lambda *_args, **_kwargs: FakeResponse(status_code=500))
    assert not lab._kusto_status().healthy

    def fail(*_args: object, **_kwargs: object) -> None:
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(lab.httpx, "post", fail)
    assert not lab._kusto_status().healthy


def test_duckdb_status_is_embedded_version() -> None:
    status = lab._duckdb_status()
    assert status.healthy
    assert status.detail.startswith("v")


def test_status_returns_all_components(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        lab,
        "_opensearch_status",
        lambda: ServiceStatus("opensearch", "http://os", True, "green"),
    )
    monkeypatch.setattr(
        lab,
        "_dashboards_status",
        lambda: ServiceStatus("dashboards", "http://dash", True, "HTTP 200"),
    )
    monkeypatch.setattr(
        lab, "_kusto_status", lambda: ServiceStatus("kusto", "http://k", True, "HTTP 200")
    )
    monkeypatch.setattr(
        lab, "_duckdb_status", lambda: ServiceStatus("duckdb", "embedded", True, "v")
    )

    statuses = lab.status()
    assert [item.name for item in statuses] == [
        "opensearch",
        "dashboards",
        "kusto",
        "duckdb",
    ]
    assert all(item.healthy for item in statuses)


def test_wait_returns_when_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        lab,
        "status",
        lambda: [ServiceStatus("opensearch", "http://os", True, "green")],
    )
    statuses = lab.wait(timeout=1)
    assert statuses[0].healthy


def test_wait_polls_until_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    statuses = iter(
        [
            [ServiceStatus("opensearch", "http://os", False, "starting")],
            [ServiceStatus("opensearch", "http://os", True, "green")],
        ]
    )
    times = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr(lab, "status", lambda: next(statuses))
    monkeypatch.setattr(lab.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(lab.time, "sleep", lambda _seconds: None)

    result = lab.wait(timeout=10, interval=0)
    assert result[0].healthy


def test_wait_raises_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        lab,
        "status",
        lambda: [ServiceStatus("opensearch", "http://os", False, "starting")],
    )
    with pytest.raises(LabError, match="did not become healthy"):
        lab.wait(timeout=0)


def test_apply_opensearch_templates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lab.config, "OPENSEARCH_TEMPLATES", {"edl-test": Path("template.json")})
    monkeypatch.setattr(lab, "read_json", lambda _path: {"index_patterns": ["*"]})
    monkeypatch.setattr(lab.httpx, "put", lambda *_args, **_kwargs: FakeResponse())
    lab._apply_opensearch_templates()


def test_apply_opensearch_templates_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lab.config, "OPENSEARCH_TEMPLATES", {"edl-test": Path("template.json")})
    monkeypatch.setattr(lab, "read_json", lambda _path: {})
    monkeypatch.setattr(
        lab.httpx,
        "put",
        lambda *_args, **_kwargs: FakeResponse(status_code=400, text="bad template"),
    )
    with pytest.raises(LabError, match="bad template"):
        lab._apply_opensearch_templates()


def test_apply_kusto_bootstrap_runs_each_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap = tmp_path / "bootstrap.kql"
    bootstrap.write_text("// comment\n.show tables\n\n.create table Events\n", encoding="utf-8")
    monkeypatch.setattr(lab.config, "KUSTO_BOOTSTRAP", bootstrap)

    calls: list[dict[str, str]] = []

    def fake_post(_url: str, *, json: dict[str, str], **_kwargs: object) -> FakeResponse:
        calls.append(json)
        return FakeResponse(payload={})

    monkeypatch.setattr(lab.httpx, "post", fake_post)
    lab._apply_kusto_bootstrap()
    assert [call["csl"] for call in calls] == [".show tables", ".create table Events"]
    assert all(call["db"] == lab.config.KUSTO_DB for call in calls)


def test_apply_kusto_bootstrap_rejects_empty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap = tmp_path / "bootstrap.kql"
    bootstrap.write_text("// only a comment\n", encoding="utf-8")
    monkeypatch.setattr(lab.config, "KUSTO_BOOTSTRAP", bootstrap)
    with pytest.raises(LabError, match="No Kusto commands"):
        lab._apply_kusto_bootstrap()


def test_apply_kusto_bootstrap_reports_http_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap = tmp_path / "bootstrap.kql"
    bootstrap.write_text(".show tables\n", encoding="utf-8")
    monkeypatch.setattr(lab.config, "KUSTO_BOOTSTRAP", bootstrap)
    monkeypatch.setattr(
        lab.httpx,
        "post",
        lambda *_args, **_kwargs: FakeResponse(status_code=500, text="kusto down"),
    )
    with pytest.raises(LabError, match="kusto down"):
        lab._apply_kusto_bootstrap()


def test_apply_kusto_bootstrap_reports_non_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap = tmp_path / "bootstrap.kql"
    bootstrap.write_text(".show tables\n", encoding="utf-8")
    monkeypatch.setattr(lab.config, "KUSTO_BOOTSTRAP", bootstrap)
    monkeypatch.setattr(
        lab.httpx,
        "post",
        lambda *_args, **_kwargs: FakeResponse(invalid_json=True, text="not json"),
    )
    with pytest.raises(LabError, match="non-JSON"):
        lab._apply_kusto_bootstrap()


def test_apply_kusto_bootstrap_reports_kusto_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap = tmp_path / "bootstrap.kql"
    bootstrap.write_text(".show tables\n", encoding="utf-8")
    monkeypatch.setattr(lab.config, "KUSTO_BOOTSTRAP", bootstrap)
    monkeypatch.setattr(
        lab.httpx,
        "post",
        lambda *_args, **_kwargs: FakeResponse(payload={"error": "syntax error"}),
    )
    with pytest.raises(LabError, match="syntax error"):
        lab._apply_kusto_bootstrap()


def test_apply_duckdb_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database = tmp_path / "nested" / "edl.duckdb"
    schema = tmp_path / "schema.sql"
    schema.write_text(
        "CREATE TABLE events (id INTEGER);\nINSERT INTO events VALUES (1);\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(lab.config, "DUCKDB_PATH", database)
    monkeypatch.setattr(lab.config, "DUCKDB_SCHEMA", schema)

    lab._apply_duckdb_schema()
    with duckdb.connect(str(database)) as connection:
        assert connection.execute("SELECT id FROM events").fetchall() == [(1,)]


def test_apply_duckdb_schema_rejects_empty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    schema = tmp_path / "schema.sql"
    schema.write_text(";\n", encoding="utf-8")
    monkeypatch.setattr(lab.config, "DUCKDB_PATH", tmp_path / "edl.duckdb")
    monkeypatch.setattr(lab.config, "DUCKDB_SCHEMA", schema)
    with pytest.raises(LabError, match="No SQL statements"):
        lab._apply_duckdb_schema()


def test_bootstrap_calls_each_step(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(lab, "wait", lambda: calls.append("wait"))
    monkeypatch.setattr(lab, "_apply_opensearch_templates", lambda: calls.append("opensearch"))
    monkeypatch.setattr(lab, "_apply_kusto_bootstrap", lambda: calls.append("kusto"))
    monkeypatch.setattr(lab, "_apply_duckdb_schema", lambda: calls.append("duckdb"))

    lab.bootstrap()
    assert calls == ["wait", "opensearch", "kusto", "duckdb"]
