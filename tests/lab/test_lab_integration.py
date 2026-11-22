from __future__ import annotations

import pytest

from edl import lab

pytestmark = pytest.mark.lab


def test_lab_is_healthy() -> None:
    statuses = lab.status()
    assert statuses
    assert all(item.healthy for item in statuses), statuses
