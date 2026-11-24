from __future__ import annotations

from pathlib import Path

import pytest

from edl.errors import ValidationError
from edl.tenant import accepted_mail_domains, clear_cache, load_tenant_config


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_load_tenant_config_from_repository() -> None:
    config = load_tenant_config()
    assert config.accepted_mail_domains == frozenset({"example.test"})
    assert config.path.name == "tenant.yaml"
    assert "example.test" in accepted_mail_domains()


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
