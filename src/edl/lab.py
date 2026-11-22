"""Local lab lifecycle and health checks."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

import duckdb
import httpx

from . import config
from .errors import LabError
from .utils import read_json, run, split_kusto_commands, split_sql


@dataclass(frozen=True)
class ServiceStatus:
    """Health of one local lab component."""

    name: str
    url: str
    healthy: bool
    detail: str


def compose_command(*args: str) -> list[str]:
    """Build a docker compose command for this repository."""
    return ["docker", "compose", "-f", str(config.COMPOSE_FILE), *args]


def compose(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    """Run docker compose in the repository directory."""
    return run(compose_command(*args), capture=capture)


def up() -> None:
    """Start the core lab and wait for it to become healthy."""
    compose("up", "-d")
    wait()


def down() -> None:
    """Stop the lab without deleting data."""
    compose("down")


def reset() -> None:
    """Stop the lab and delete its named volumes."""
    compose("down", "-v")


def logs(service: str | None = None, follow: bool = True) -> None:
    """Stream compose logs."""
    args = ["logs"]
    if follow:
        args.append("-f")
    if service:
        args.append(service)
    compose(*args, capture=False)


def _opensearch_status() -> ServiceStatus:
    url = config.OPENSEARCH_URL
    try:
        response = httpx.get(f"{url}/_cluster/health", timeout=2.0)
        if response.status_code != 200:
            return ServiceStatus("opensearch", url, False, f"HTTP {response.status_code}")
        status = str(response.json().get("status", "unknown"))
        return ServiceStatus("opensearch", url, status in {"green", "yellow"}, status)
    except (httpx.HTTPError, ValueError) as exc:
        return ServiceStatus("opensearch", url, False, str(exc))


def _dashboards_status() -> ServiceStatus:
    url = config.DASHBOARDS_URL
    try:
        response = httpx.get(f"{url}/api/status", timeout=2.0)
        healthy = response.status_code == 200
        return ServiceStatus("opensearch-dashboards", url, healthy, f"HTTP {response.status_code}")
    except httpx.HTTPError as exc:
        return ServiceStatus("opensearch-dashboards", url, False, str(exc))


def _kusto_status() -> ServiceStatus:
    url = config.KUSTO_URL
    try:
        response = httpx.post(
            f"{url}/v1/rest/mgmt",
            json={"csl": ".show cluster"},
            timeout=2.0,
        )
        healthy = response.status_code == 200
        return ServiceStatus("kusto", url, healthy, f"HTTP {response.status_code}")
    except httpx.HTTPError as exc:
        return ServiceStatus("kusto", url, False, str(exc))


def _duckdb_status() -> ServiceStatus:
    try:
        with duckdb.connect(":memory:") as connection:
            version = connection.execute("SELECT version()").fetchone()
        detail = str(version[0]) if version else "unknown"
        return ServiceStatus("duckdb", "embedded", True, detail)
    except Exception as exc:  # pragma: no cover - import/runtime failure
        return ServiceStatus("duckdb", "embedded", False, str(exc))


def status() -> list[ServiceStatus]:
    """Return the health of every local lab component."""
    return [
        _opensearch_status(),
        _dashboards_status(),
        _kusto_status(),
        _duckdb_status(),
    ]


def wait(timeout: int = 180, interval: float = 3.0) -> list[ServiceStatus]:
    """Wait until every component is healthy or the timeout expires."""
    deadline = time.monotonic() + timeout
    latest = status()
    while time.monotonic() < deadline:
        if all(item.healthy for item in latest):
            return latest
        time.sleep(interval)
        latest = status()
    unhealthy = [item.name for item in latest if not item.healthy]
    raise LabError(f"Lab did not become healthy within {timeout}s: {', '.join(unhealthy)}")


def _apply_opensearch_templates() -> None:
    for name, path in config.OPENSEARCH_TEMPLATES.items():
        payload = read_json(path)
        response = httpx.put(
            f"{config.OPENSEARCH_URL}/_index_template/{name}",
            json=payload,
            timeout=10.0,
        )
        if response.status_code >= 300:
            raise LabError(
                f"OpenSearch template {name} failed with HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )


def _apply_kusto_bootstrap() -> None:
    commands = split_kusto_commands(config.KUSTO_BOOTSTRAP.read_text(encoding="utf-8"))
    if not commands:
        raise LabError(f"No Kusto commands found in {config.KUSTO_BOOTSTRAP}")

    for command in commands:
        body: dict[str, str] = {"db": config.KUSTO_DB, "csl": command}
        response = httpx.post(
            f"{config.KUSTO_URL}/v1/rest/mgmt",
            json=body,
            timeout=30.0,
        )
        if response.status_code >= 300:
            raise LabError(
                f"Kusto bootstrap failed with HTTP {response.status_code}: {response.text[:300]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise LabError(f"Kusto returned non-JSON response: {response.text[:300]}") from exc
        if isinstance(payload, dict) and payload.get("error"):
            raise LabError(f"Kusto error: {payload['error']}")


def _apply_duckdb_schema() -> None:
    config.DUCKDB_PATH.parent.mkdir(parents=True, exist_ok=True)
    statements = split_sql(config.DUCKDB_SCHEMA.read_text(encoding="utf-8"))
    if not statements:
        raise LabError(f"No SQL statements found in {config.DUCKDB_SCHEMA}")
    with duckdb.connect(str(config.DUCKDB_PATH)) as connection:
        for statement in statements:
            connection.execute(statement)


def bootstrap() -> None:
    """Apply OpenSearch templates, Kusto schema, and DuckDB schema."""
    wait()
    _apply_opensearch_templates()
    _apply_kusto_bootstrap()
    _apply_duckdb_schema()
