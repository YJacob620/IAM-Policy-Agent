from __future__ import annotations

from typing import Any

from models.policy import PolicyModel


READ_ONLY_PREFIXES = ("Get", "List", "Describe", "View", "Lookup")
RESOURCE_TYPE_TOKENS = {
    "bucket",
    "cluster",
    "function",
    "group",
    "instance",
    "key",
    "log-group",
    "policy",
    "queue",
    "repository",
    "role",
    "secret",
    "table",
    "topic",
    "user",
}


def unwrap_policy_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TypeError("Policy payload must be a JSON object.")

    policy = payload.get("policy", payload)
    if not isinstance(policy, dict):
        raise TypeError("Wrapped policy payload must contain a policy object.")
    return policy


def validate_policy_document(policy: dict[str, Any]) -> dict[str, Any]:
    validated = PolicyModel.model_validate(policy)
    return validated.model_dump(exclude_none=True)


def normalize_to_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statement_sid(statement: dict[str, Any], index: int) -> str:
    return str(statement.get("Sid") or f"Statement{index}")


def is_allow_statement(statement: dict[str, Any]) -> bool:
    return str(statement.get("Effect", "")).lower() == "allow"


def has_condition(statement: dict[str, Any]) -> bool:
    condition = statement.get("Condition")
    return isinstance(condition, dict) and bool(condition)


def contains_wildcard_token(value: Any) -> bool:
    return isinstance(value, str) and ("*" in value or "?" in value)


def is_action_wildcard(action: Any) -> bool:
    return isinstance(action, str) and contains_wildcard_token(action)


def is_resource_broad(resource: Any) -> bool:
    if not isinstance(resource, str):
        return False
    if resource == "*":
        return True
    if not resource.startswith("arn:"):
        return False

    resource_part = resource.split(":", 5)[5] if len(resource.split(":", 5)) > 5 else ""
    if not resource_part or resource_part == "*" or resource_part.startswith("*"):
        return True

    for delimiter in (":", "/"):
        marker = f"{delimiter}*"
        if marker not in resource_part:
            continue

        prefix = resource_part.split(marker, 1)[0]
        normalized_prefix = prefix.replace("/", ":")
        last_token = normalized_prefix.split(":")[-1] if normalized_prefix else ""
        if not prefix or last_token in RESOURCE_TYPE_TOKENS:
            return True

    return False


def action_name(action: str) -> str:
    if ":" not in action:
        return action
    return action.split(":", 1)[1]


def is_read_only_action(action: Any) -> bool:
    if not isinstance(action, str) or contains_wildcard_token(action):
        return False
    return action_name(action).startswith(READ_ONLY_PREFIXES)


def infer_services_from_statement(statement: dict[str, Any]) -> set[str]:
    services: set[str] = set()

    for key in ("Action", "NotAction"):
        for value in normalize_to_list(statement.get(key)):
            if not isinstance(value, str) or ":" not in value:
                continue
            service = value.split(":", 1)[0].strip().lower()
            if service and service != "*":
                services.add(service)

    for key in ("Resource", "NotResource"):
        for value in normalize_to_list(statement.get(key)):
            if not isinstance(value, str) or not value.startswith("arn:"):
                continue
            parts = value.split(":", 5)
            if len(parts) > 2 and parts[2] and parts[2] != "*":
                services.add(parts[2].lower())

    return services


def needs_condition_review(statement: dict[str, Any]) -> bool:
    if not is_allow_statement(statement) or has_condition(statement):
        return False

    actions = [
        action
        for action in normalize_to_list(statement.get("Action"))
        if isinstance(action, str)
    ]
    broad_actions = any(is_action_wildcard(action) for action in actions)
    broad_resources = any(
        is_resource_broad(resource)
        for resource in normalize_to_list(statement.get("Resource"))
    )
    privileged_identity_actions = any(
        action.startswith(("iam:", "sts:")) and not is_read_only_action(action)
        for action in actions
    )

    return broad_actions or broad_resources or privileged_identity_actions
