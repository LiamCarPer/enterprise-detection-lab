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
class ApprovedApplication:
    """One reviewed application entry from tenant configuration."""

    app_id: str
    display_name: str
    owner_organization_id: str
    publisher: str
    redirect_uris: frozenset[str]


@dataclass(frozen=True)
class PublisherReputationEntry:
    """One publisher reputation entry from tenant configuration."""

    organization_id: str
    publisher: str
    reputation: str


@dataclass(frozen=True)
class TenantConfig:
    """Validated tenant configuration loaded from disk."""

    path: Path
    accepted_mail_domains: frozenset[str]
    approved_applications: tuple[ApprovedApplication, ...] = ()
    publisher_reputations: tuple[PublisherReputationEntry, ...] = ()

    def approved_application(
        self,
        app_id: str | None,
        redirect_uri: str | None,
    ) -> ApprovedApplication | None:
        """Return the approved entry for an application and redirect URI, if any."""
        if not app_id:
            return None
        for application in self.approved_applications:
            if application.app_id != app_id:
                continue
            if redirect_uri and redirect_uri not in application.redirect_uris:
                return None
            return application
        return None

    def publisher_reputation(self, owner_organization_id: str | None) -> str:
        """Return the configured publisher reputation or unknown."""
        if not owner_organization_id:
            return "unknown"
        for entry in self.publisher_reputations:
            if entry.organization_id == owner_organization_id:
                return entry.reputation
        return "unknown"


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
    approved: list[ApprovedApplication] = []
    for item in data.get("approved_applications", []):
        raw_redirects = item.get("redirect_uris", [])
        approved.append(
            ApprovedApplication(
                app_id=str(item["app_id"]),
                display_name=str(item["display_name"]),
                owner_organization_id=str(item["owner_organization_id"]),
                publisher=str(item["publisher"]),
                redirect_uris=frozenset(str(uri) for uri in raw_redirects),
            )
        )
    reputations = [
        PublisherReputationEntry(
            organization_id=str(item["organization_id"]),
            publisher=str(item["publisher"]),
            reputation=str(item["reputation"]),
        )
        for item in data.get("publisher_reputation", [])
    ]
    return TenantConfig(
        path=target,
        accepted_mail_domains=frozenset(domains),
        approved_applications=tuple(approved),
        publisher_reputations=tuple(reputations),
    )


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


def approved_application(
    app_id: str | None, redirect_uri: str | None = None
) -> ApprovedApplication | None:
    """Return the configured approved application, if any."""
    return load_tenant_config().approved_application(app_id, redirect_uri)


def publisher_reputation(owner_organization_id: str | None) -> str:
    """Return the configured publisher reputation or unknown."""
    return load_tenant_config().publisher_reputation(owner_organization_id)


def clear_cache() -> None:
    """Clear the tenant configuration cache."""
    _load_cached.cache_clear()
