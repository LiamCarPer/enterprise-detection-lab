from __future__ import annotations

from pathlib import Path

import pytest

from edl.utils import read_json, run, sha256_file, split_kusto_commands, split_sql


def test_run_executes_command() -> None:
    result = run(["true"])
    assert result.returncode == 0


def test_read_json_missing_and_invalid(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="JSON file not found"):
        read_json(tmp_path / "missing.json")

    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        read_json(bad)


def test_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "data.txt"
    path.write_bytes(b"abc")
    assert sha256_file(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_split_helpers_handle_empty_input() -> None:
    assert split_kusto_commands("// comment only\n") == []
    assert split_sql("") == []
