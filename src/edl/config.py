"""Repository paths and runtime configuration."""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "compose.yaml"
SCHEMAS_DIR = ROOT / "schemas"

OPENSEARCH_URL = os.getenv("EDL_OPENSEARCH_URL", "http://127.0.0.1:9200").rstrip("/")
DASHBOARDS_URL = os.getenv("EDL_DASHBOARDS_URL", "http://127.0.0.1:5601").rstrip("/")
KUSTO_URL = os.getenv("EDL_KUSTO_URL", "http://127.0.0.1:18080").rstrip("/")
KUSTO_DB = os.getenv("EDL_KUSTO_DB", "NetDefaultDB")
TENANT_CONFIG = ROOT / "config" / "tenant.yaml"

_index_prefix = os.getenv("EDL_EVENTS_INDEX_PREFIX", "edl-events").strip("-")
EVENTS_INDEX_PREFIX = _index_prefix or "edl-events"

_duckdb_path = Path(os.getenv("EDL_DUCKDB_PATH", "lab/data/duckdb/edl.duckdb"))
DUCKDB_PATH = _duckdb_path if _duckdb_path.is_absolute() else ROOT / _duckdb_path

OPENSEARCH_TEMPLATES_DIR = ROOT / "lab" / "bootstrap" / "opensearch"
KUSTO_BOOTSTRAP = ROOT / "lab" / "bootstrap" / "kusto" / "bootstrap.kql"
DUCKDB_SCHEMA = ROOT / "lab" / "bootstrap" / "duckdb" / "schema.sql"

OPENSEARCH_TEMPLATES = {
    "edl-events-v1": OPENSEARCH_TEMPLATES_DIR / "events-template.json",
    "edl-findings-v1": OPENSEARCH_TEMPLATES_DIR / "findings-template.json",
}
