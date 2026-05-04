from __future__ import annotations

from typing import Any

from utils.validators import (
    has_condition,
    is_action_wildcard,
    is_allow_statement,
    is_read_only_action,
    is_resource_broad,
    needs_condition_review,
    normalize_to_list,
    statement_sid,
)


def _iter_statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    return list(statements)


def check_wildcards(policy: dict[str, Any]) -> dict[str, Any]:
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

    return {
        "wildcards_found": bool(findings),
        "findings": findings,
        "recommendation": "Replace wildcard action patterns with explicit service actions.",
    }


def check_resource_scope(policy: dict[str, Any]) -> dict[str, Any]:
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

    return {
        "unrestricted_resources": bool(findings),
        "findings": findings,
        "recommendation": "Scope resources to specific ARNs when the service supports resource-level permissions.",
    }


def check_conditions(policy: dict[str, Any]) -> dict[str, Any]:
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

    return {
        "missing_conditions": bool(findings),
        "findings": findings,
        "recommendation": "Add conditions to broad Allow statements to enforce contextual restrictions.",
    }


def check_not_actions(policy: dict[str, Any]) -> dict[str, Any]:
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

    return {
        "not_actions_found": bool(findings),
        "findings": findings,
        "recommendation": "Replace NotAction with an explicit allow-list of the required actions.",
    }


def check_effect_allow_star(policy: dict[str, Any]) -> dict[str, Any]:
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

    return {
        "allow_star_found": bool(findings),
        "findings": findings,
        "recommendation": "Break full-admin statements into narrowly scoped permissions with explicit actions and resources.",
    }
