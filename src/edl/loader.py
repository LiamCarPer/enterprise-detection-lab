"""Safe YAML and JSON loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.constructor import DuplicateKeyError

from .errors import ValidationError


def load_yaml(path: Path) -> Any:
    """Load YAML with duplicate-key rejection."""
    yaml = YAML(typ="safe")
    yaml.allow_duplicate_keys = False
    try:
        return yaml.load(path.read_text(encoding="utf-8"))
    except DuplicateKeyError as exc:
        raise ValidationError(f"Duplicate YAML key in {path}: {exc}") from exc
    except OSError as exc:
        raise ValidationError(f"Cannot read YAML file {path}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - ruamel raises several parser types
        raise ValidationError(f"Invalid YAML in {path}: {exc}") from exc


def load_json(path: Path) -> Any:
    """Load JSON with a useful error message."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValidationError(f"Cannot read JSON file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Invalid JSON in {path}: {exc}") from exc


def load_mapping(path: Path) -> dict[str, Any]:
    """Load a YAML mapping and reject non-mapping documents."""
    data = load_yaml(path)
    if not isinstance(data, dict):
        raise ValidationError(f"Expected a mapping in {path}")
    return data
