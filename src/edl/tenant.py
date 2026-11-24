"""Versioned tenant configuration."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from . import config
from .errors import ValidationError
from .loader import load_json, load_mapping


@dataclass(frozen=True)
class TenantConfig:
    """Validated tenant configuration loaded from disk."""

    path: Path
    accepted_mail_domains: frozenset[str]


@lru_cache(maxsize=8)
def _load_cached(path: str, mtime_ns: int) -> TenantConfig:
    target = Path(path)
    data = load_mapping(target)
    schema_path = config.SCHEMAS_DIR / "tenant.schema.json"
    try:
        schema: Any = load_json(schema_path)
    except ValidationError as exc:
        raise ValidationError(f"Cannot load tenant schema {schema_path}: {exc}") from exc

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(data),
        key=lambda error: tuple(str(part) for part in error.path),
    )
    if errors:
        details = "; ".join(error.message for error in errors[:3])
        raise ValidationError(f"{target}: {details}")

    domains = [str(item) for item in data["accepted_mail_domains"]]
    return TenantConfig(path=target, accepted_mail_domains=frozenset(domains))


def load_tenant_config(path: Path | None = None) -> TenantConfig:
    """Load and validate the tenant configuration."""
    target = path or config.TENANT_CONFIG
    try:
        mtime_ns = target.stat().st_mtime_ns
    except OSError as exc:
        raise ValidationError(f"Cannot read tenant configuration {target}: {exc}") from exc
    return _load_cached(str(target), mtime_ns)


def accepted_mail_domains() -> set[str]:
    """Return the configured domains treated as internal."""
    return set(load_tenant_config().accepted_mail_domains)


def clear_cache() -> None:
    """Clear the tenant configuration cache."""
    _load_cached.cache_clear()
