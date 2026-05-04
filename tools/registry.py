from __future__ import annotations

from typing import Any, Callable

from tools.analysis_tools import (
    check_conditions,
    check_effect_allow_star,
    check_not_actions,
    check_resource_scope,
    check_wildcards,
)
from tools.remediation_tool import remediate_policy


TOOLS: dict[str, Callable[..., dict[str, Any]]] = {
    "check_wildcards": check_wildcards,
    "check_resource_scope": check_resource_scope,
    "check_conditions": check_conditions,
    "check_not_actions": check_not_actions,
    "check_effect_allow_star": check_effect_allow_star,
    "remediate_policy": remediate_policy,
}

TOOL_SCHEMAS = [
    {
        "name": "check_wildcards",
        "description": "Scans Allow statements for wildcard Action values such as '*' or 's3:*'.",
        "parameters": {"policy": "The validated IAM policy document."},
        "returns": "{ wildcards_found: bool, findings: [...] }",
    },
    {
        "name": "check_resource_scope",
        "description": "Detects broad Resource values such as '*' or ARN wildcards.",
        "parameters": {"policy": "The validated IAM policy document."},
        "returns": "{ unrestricted_resources: bool, findings: [...] }",
    },
    {
        "name": "check_conditions",
        "description": "Flags broad Allow statements that lack compensating conditions.",
        "parameters": {"policy": "The validated IAM policy document."},
        "returns": "{ missing_conditions: bool, findings: [...] }",
    },
    {
        "name": "check_not_actions",
        "description": "Detects NotAction usage in Allow statements.",
        "parameters": {"policy": "The validated IAM policy document."},
        "returns": "{ not_actions_found: bool, findings: [...] }",
    },
    {
        "name": "check_effect_allow_star",
        "description": "Identifies Allow statements that combine Action:* and Resource:*.",
        "parameters": {"policy": "The validated IAM policy document."},
        "returns": "{ allow_star_found: bool, findings: [...] }",
    },
    {
        "name": "remediate_policy",
        "description": "Produces a remediated policy, a change list, and remediation reasoning.",
        "parameters": {
            "policy": "The validated IAM policy document.",
            "findings": "The material findings collected during analysis.",
        },
        "returns": "{ remediated_policy: {...}, changes: [...], reasoning: str }",
    },
]


def dispatch_tool(tool_name: str, **kwargs: Any) -> dict[str, Any]:
    if tool_name not in TOOLS:
        raise KeyError(f"Unknown tool: {tool_name}")
    return TOOLS[tool_name](**kwargs)
