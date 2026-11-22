"""Small, dependency-free helpers."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .config import ROOT


def run(
    command: Sequence[str],
    *,
    cwd: Path = ROOT,
    capture: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command with predictable text handling."""
    return subprocess.run(
        list(command),
        cwd=str(cwd),
        check=check,
        text=True,
        capture_output=capture,
    )


def read_json(path: Path) -> Any:
    """Read a JSON file with a clear error if it is missing or malformed."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"JSON file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_kusto_commands(text: str) -> list[str]:
    """Split a Kusto bootstrap file into commands separated by blank lines.

    Lines beginning with `//` are treated as comments. Kusto management
    commands may span multiple lines; a blank line terminates a command.
    """
    commands: list[str] = []
    current: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            if current:
                commands.append("\n".join(current).strip())
                current = []
            continue
        current.append(line)

    if current:
        commands.append("\n".join(current).strip())

    return [command for command in commands if command]


def split_sql(text: str) -> list[str]:
    """Split a simple SQL bootstrap file on semicolons."""
    return [statement.strip() for statement in text.split(";") if statement.strip()]
