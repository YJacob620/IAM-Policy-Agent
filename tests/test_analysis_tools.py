from __future__ import annotations

import json
from pathlib import Path

from tools.analysis_tools import (
    check_conditions,
    check_effect_allow_star,
    check_not_actions,
    check_resource_scope,
    check_wildcards,
)
from utils.validators import unwrap_policy_payload, validate_policy_document


FIXTURE_DIR = Path(__file__).parent / "sample_policies"


def load_fixture(name: str) -> dict:
    raw = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
    return validate_policy_document(unwrap_policy_payload(raw))


def test_check_wildcards_detects_admin_star() -> None:
    result = check_wildcards(load_fixture("weak1.json"))

    assert result["wildcards_found"] is True
    assert result["findings"][0]["severity"] == "CRITICAL"


def test_check_effect_allow_star_detects_full_admin() -> None:
    result = check_effect_allow_star(load_fixture("weak1.json"))

    assert result["allow_star_found"] is True
    assert result["findings"][0]["severity"] == "CRITICAL"


def test_check_not_actions_flags_allow_not_action() -> None:
    result = check_not_actions(load_fixture("weak4.json"))

    assert result["not_actions_found"] is True
    assert result["findings"][0]["severity"] == "CRITICAL"


def test_check_resource_scope_downgrades_condition_scoped_resource_star() -> None:
    result = check_resource_scope(load_fixture("strong4.json"))

    assert result["unrestricted_resources"] is True
    assert result["findings"][0]["severity"] == "LOW"


def test_check_conditions_flags_broad_allow_without_condition() -> None:
    result = check_conditions(load_fixture("weak6.json"))

    assert result["missing_conditions"] is True
    assert result["findings"][0]["severity"] == "HIGH"


def test_check_conditions_ignores_constrained_policy() -> None:
    result = check_conditions(load_fixture("strong1.json"))

    assert result["missing_conditions"] is False
