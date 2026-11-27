from __future__ import annotations

from pathlib import Path

import pytest

from edl.errors import ValidationError
from edl.tenant import (
    accepted_mail_domains,
    approved_application,
    clear_cache,
    load_tenant_config,
    publisher_reputation,
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_load_tenant_config_from_repository() -> None:
    config = load_tenant_config()
    assert config.accepted_mail_domains == frozenset({"example.test"})
    assert config.path.name == "tenant.yaml"
    assert "example.test" in accepted_mail_domains()
    assert len(config.approved_applications) == 2
    assert len(config.publisher_reputations) == 3


def test_load_tenant_config_custom_path(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "tenant.yaml",
        "version: 1\naccepted_mail_domains:\n  - example.net\n  - example.org\n",
    )
    config = load_tenant_config(path)
    assert config.accepted_mail_domains == frozenset({"example.net", "example.org"})


def test_load_tenant_config_rejects_missing_domains(tmp_path: Path) -> None:
    path = _write(tmp_path / "tenant.yaml", "version: 1\n")
    with pytest.raises(ValidationError, match="accepted_mail_domains"):
        load_tenant_config(path)


def test_load_tenant_config_rejects_uppercase_domain(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "tenant.yaml",
        "version: 1\naccepted_mail_domains:\n  - Example.Test\n",
    )
    with pytest.raises(ValidationError):
        load_tenant_config(path)


def test_load_tenant_config_rejects_invalid_domain(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "tenant.yaml",
        "version: 1\naccepted_mail_domains:\n  - localhost\n",
    )
    with pytest.raises(ValidationError):
        load_tenant_config(path)


def test_load_tenant_config_rejects_duplicate_domains(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "tenant.yaml",
        "version: 1\naccepted_mail_domains:\n  - example.test\n  - example.test\n",
    )
    with pytest.raises(ValidationError):
        load_tenant_config(path)


def test_load_tenant_config_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="Cannot read tenant configuration"):
        load_tenant_config(tmp_path / "missing.yaml")


def test_clear_cache_reloads_changed_config(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "tenant.yaml",
        "version: 1\naccepted_mail_domains:\n  - example.test\n",
    )
    assert load_tenant_config(path).accepted_mail_domains == frozenset({"example.test"})
    _write(
        path,
        "version: 1\naccepted_mail_domains:\n  - example.net\n",
    )
    clear_cache()
    assert load_tenant_config(path).accepted_mail_domains == frozenset({"example.net"})


def test_load_tenant_config_reports_missing_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _write(
        tmp_path / "tenant.yaml",
        "version: 1\naccepted_mail_domains:\n  - example.test\n",
    )
    monkeypatch.setattr("edl.tenant.config.SCHEMAS_DIR", tmp_path / "missing-schemas")
    with pytest.raises(ValidationError, match="Cannot load tenant schema"):
        load_tenant_config(path)


def test_approved_application_requires_matching_app_and_redirect() -> None:
    config = load_tenant_config()
    app_id = "00000000-0000-4000-8000-000000009101"
    approved = config.approved_application(app_id, "https://login.approved.example/callback")
    assert approved is not None
    assert approved.display_name == "Approved Analytics"
    assert config.approved_application(app_id, None) is not None
    assert config.approved_application(app_id, "https://login.approved.example/other") is None
    assert config.approved_application("00000000-0000-4000-8000-000000009199", None) is None
    assert config.approved_application(None, None) is None


def test_module_helpers_read_approved_application_and_reputation() -> None:
    app_id = "00000000-0000-4000-8000-000000009102"
    approved = approved_application(app_id, "https://login.approved-reporting.example/callback")
    assert approved is not None
    assert approved.publisher == "Example Reporting Publisher"
    assert publisher_reputation("22222222-2222-4222-8222-222222222222") == "trusted"
    assert publisher_reputation("44444444-4444-4444-8444-444444444444") == "untrusted"
    assert publisher_reputation("55555555-5555-4555-8555-555555555555") == "unknown"
    assert publisher_reputation(None) == "unknown"


def test_load_tenant_config_rejects_invalid_reputation(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "tenant.yaml",
        "version: 1\naccepted_mail_domains:\n  - example.test\n"
        "publisher_reputation:\n"
        "  - organization_id: publisher-1\n"
        "    publisher: Example Publisher\n"
        "    reputation: suspicious\n",
    )
    with pytest.raises(ValidationError):
        load_tenant_config(path)


def test_load_tenant_config_rejects_application_without_redirect_uris(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "tenant.yaml",
        "version: 1\naccepted_mail_domains:\n  - example.test\n"
        "approved_applications:\n"
        "  - app_id: app-1\n"
        "    display_name: Example App\n"
        "    owner_organization_id: publisher-1\n"
        "    publisher: Example Publisher\n",
    )
    with pytest.raises(ValidationError, match="redirect_uris"):
        load_tenant_config(path)
