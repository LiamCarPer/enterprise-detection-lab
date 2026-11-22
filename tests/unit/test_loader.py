from __future__ import annotations

from pathlib import Path

import pytest

from edl.errors import ValidationError
from edl.loader import load_json, load_mapping, load_yaml


def test_load_valid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "valid.yaml"
    path.write_text("id: test\nvalue: 1\n", encoding="utf-8")
    assert load_yaml(path) == {"id": "test", "value": 1}


def test_load_yaml_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="Cannot read YAML"):
        load_yaml(tmp_path / "missing.yaml")


def test_load_yaml_invalid_file(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("id: [unterminated\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="Invalid YAML"):
        load_yaml(path)


def test_load_yaml_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("id: one\nid: two\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="Duplicate YAML key"):
        load_yaml(path)


def test_load_json_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="Cannot read JSON"):
        load_json(tmp_path / "missing.json")


def test_invalid_json_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ValidationError, match="Invalid JSON"):
        load_json(path)


def test_load_mapping_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="Expected a mapping"):
        load_mapping(path)
