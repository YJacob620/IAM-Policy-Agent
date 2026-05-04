from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.orchestrator import Orchestrator


FIXTURE_DIR = Path(__file__).parent / "sample_policies"
WEAK_FIXTURES = [
    "weak1.json",
    "weak2.json",
    "weak3.json",
    "weak4.json",
    "weak5.json",
    "weak6.json",
    "weak7.json",
    "weak8.json",
]
STRONG_FIXTURES = [
    "strong1.json",
    "strong2.json",
    "strong3.json",
    "strong4.json",
    "strong5.json",
    "strong6.json",
    "strong7.json",
    "strong8.json",
]


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("fixture_name", STRONG_FIXTURES)
def test_strong_fixtures_classify_strong(fixture_name: str) -> None:
    result = Orchestrator(prefer_live_model=False).run(load_fixture(fixture_name))

    assert result.classification == "Strong"
    assert result.remediated_policy is None


@pytest.mark.parametrize("fixture_name", WEAK_FIXTURES)
def test_weak_fixtures_classify_weak_and_remediate(fixture_name: str) -> None:
    result = Orchestrator(prefer_live_model=False).run(load_fixture(fixture_name))

    assert result.classification == "Weak"
    assert result.remediated_policy is not None
    assert result.changes

    statements = result.remediated_policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        assert "NotAction" not in statement
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        assert all("*" not in action and "?" not in action for action in actions)
