from __future__ import annotations

from edl.lab import compose_command
from edl.utils import split_kusto_commands, split_sql


def test_compose_command_includes_file_and_args() -> None:
    command = compose_command("up", "-d")
    assert command[:3] == ["docker", "compose", "-f"]
    assert command[-2:] == ["up", "-d"]


def test_split_kusto_commands_uses_blank_lines() -> None:
    text = """.create-merge table One (TimeGenerated:datetime)

.create-merge table Two (TimeGenerated:datetime)

// comment
.create-merge table Three (TimeGenerated:datetime)
"""
    commands = split_kusto_commands(text)
    assert commands == [
        ".create-merge table One (TimeGenerated:datetime)",
        ".create-merge table Two (TimeGenerated:datetime)",
        ".create-merge table Three (TimeGenerated:datetime)",
    ]


def test_split_sql_ignores_empty_statements() -> None:
    assert split_sql("CREATE TABLE a (x INT);\n\nCREATE TABLE b (y INT);") == [
        "CREATE TABLE a (x INT)",
        "CREATE TABLE b (y INT)",
    ]
