"""Deterministic IAM analysis tools used by the agentic review loop."""

from __future__ import annotations

from typing import Any

from utils.validators import (
    has_condition,
    is_action_wildcard,
    is_allow_statement,
    is_resource_broad,
    needs_condition_review,
    normalize_to_list,
    statement_sid,
)


def _iter_statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the policy's statements as a list regardless of original shape."""

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    return list(statements)


def check_conditions(policy: dict[str, Any]) -> dict[str, Any] | None:
    """Flag permissive Allow statements that lack compensating conditions."""

    findings: list[dict[str, Any]] = []

    for index, statement in enumerate(_iter_statements(policy)):
        if not needs_condition_review(statement):
            continue

        actions = [
            action
            for action in normalize_to_list(statement.get("Action"))
            if isinstance(action, str)
        ]
        severity = "CRITICAL" if any(action == "*" for action in actions) else "HIGH"
        findings.append(
            {
                "statement_index": index,
                "sid": statement_sid(statement, index),
                "severity": severity,
                "reason": "This permissive Allow statement lacks compensating conditions such as MFA, source IP, or resource tags.",
            }
        )

    missing_conditions: bool = bool(findings)
    if not missing_conditions:
        return None
    return {
        "missing_conditions": missing_conditions,
        "findings": findings,
        "recommendation": "Add conditions to broad Allow statements to enforce contextual restrictions.",
    }


def check_effect_allow_star(policy: dict[str, Any]) -> dict[str, Any] | None:
    """Detect administrator-equivalent statements.

    ``Effect: Allow`` combined with both ``Action: *`` and ``Resource: *`` is
    the strongest weak-policy signal in the current ruleset.
    """

    findings: list[dict[str, Any]] = []

    for index, statement in enumerate(_iter_statements(policy)):
        if not is_allow_statement(statement):
            continue

        has_action_star = any(
            action == "*" for action in normalize_to_list(statement.get("Action"))
        )
        has_resource_star = any(
            resource == "*" for resource in normalize_to_list(statement.get("Resource"))
        )
        if not has_action_star or not has_resource_star:
            continue

        findings.append(
            {
                "statement_index": index,
                "sid": statement_sid(statement, index),
                "severity": "CRITICAL",
                "reason": "Effect:Allow combined with Action:* and Resource:* is administrator-equivalent access.",
            }
        )

    allow_star_found: bool = bool(findings)
    if not allow_star_found:
        return None

    return {
        "allow_star_found": allow_star_found,
        "findings": findings,
        "recommendation": "Break full-admin statements into narrowly scoped permissions with explicit actions and resources.",
    }


def check_not_actions(policy: dict[str, Any]) -> dict[str, Any] | None:
    """Detect ``NotAction`` in Allow statements.

    The project treats this pattern as high risk because it grants everything
    except the listed actions and is easy to misread during policy review.
    """

    findings: list[dict[str, Any]] = []

    for index, statement in enumerate(_iter_statements(policy)):
        if not is_allow_statement(statement):
            continue

        not_actions = [
            value
            for value in normalize_to_list(statement.get("NotAction"))
            if isinstance(value, str)
        ]
        if not not_actions:
            continue

        findings.append(
            {
                "statement_index": index,
                "sid": statement_sid(statement, index),
                "not_action_values": not_actions,
                "severity": "CRITICAL",
                "reason": "NotAction in an Allow statement grants everything except the listed actions.",
            }
        )

    not_actions_found: bool = bool(findings)
    if not not_actions_found:
        return None

    return {
        "not_actions_found": not_actions_found,
        "findings": findings,
        "recommendation": "Replace NotAction with an explicit allow-list of the required actions.",
    }


def check_resource_scope(policy: dict[str, Any]) -> dict[str, Any] | None:
    """Detect materially broad resources in Allow statements.

    The helper preserves an important nuance from the validator layer: not all
    ARN wildcards are considered equally broad, and conditioned statements can
    be downgraded to a low-severity observation instead of a weak verdict.
    """

    findings: list[dict[str, Any]] = []

    for index, statement in enumerate(_iter_statements(policy)):
        if not is_allow_statement(statement):
            continue

        broad_resources = [
            resource
            for resource in normalize_to_list(statement.get("Resource"))
            if is_resource_broad(resource)
        ]
        if not broad_resources:
            continue

        broad_actions = any(
            is_action_wildcard(action)
            for action in normalize_to_list(statement.get("Action"))
        )
        severity = "LOW" if has_condition(statement) and not broad_actions else "HIGH"
        findings.append(
            {
                "statement_index": index,
                "sid": statement_sid(statement, index),
                "resource_values": broad_resources,
                "severity": severity,
                "reason": "Unrestricted resources widen the blast radius of an Allow statement.",
            }
        )

    unrestricted_resources: bool = bool(findings)
    if not unrestricted_resources:
        return None

    return {
        "unrestricted_resources": unrestricted_resources,
        "findings": findings,
        "recommendation": "Scope resources to specific ARNs when the service supports resource-level permissions.",
    }


def check_wildcards(policy: dict[str, Any]) -> dict[str, Any] | None:
    """Detect wildcard actions in Allow statements.

    Wildcard actions are treated as material least-privilege failures because
    they expand the permission surface beyond a narrow allow-list.
    """

    findings: list[dict[str, Any]] = []

    for index, statement in enumerate(_iter_statements(policy)):
        if not is_allow_statement(statement):
            continue

        for action in normalize_to_list(statement.get("Action")):
            if not is_action_wildcard(action):
                continue

            severity = "CRITICAL" if action == "*" else "HIGH"
            findings.append(
                {
                    "statement_index": index,
                    "sid": statement_sid(statement, index),
                    "action_value": action,
                    "severity": severity,
                    "reason": "Wildcard actions expand permissions beyond least privilege.",
                }
            )

    wildcards_found: bool = bool(findings)
    if not wildcards_found:
        return None

    return {
        "wildcards_found": wildcards_found,
        "findings": findings,
        "recommendation": "Replace wildcard action patterns with explicit service actions.",
    }


def run_all_analysis_tools(policy: dict[str, Any]) -> dict[str, dict[str, Any]] | str:
    """Execute every deterministic analysis tool over the same policy.

    Tools that return None (no findings) are omitted from the result. If every
    tool returns None the function returns a clean-bill-of-health message
    instead of an empty dict.
    """

    results = {
        tool_name: result
        for tool_name, tool_callable in {
            "check_conditions": check_conditions,
            "check_effect_allow_star": check_effect_allow_star,
            "check_not_actions": check_not_actions,
            "check_resource_scope": check_resource_scope,
            "check_wildcards": check_wildcards,
        }.items()
        if (result := tool_callable(policy=policy)) is not None
    }

    if not results:
        return "No security risks detected from tools - policy is likely strong"

    return results
