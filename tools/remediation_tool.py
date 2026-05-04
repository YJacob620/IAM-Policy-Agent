from __future__ import annotations
import copy
import json
import os
from typing import Any
from utils.validators import (
    has_condition,
    infer_services_from_statement,
    is_action_wildcard,
    is_allow_statement,
    is_read_only_action,
    is_resource_broad,
    normalize_to_list,
    statement_sid,
    validate_policy_document,
)
from google import genai
from google.genai import types

MFA_CONDITION = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
SAFE_ACTIONS_BY_SERVICE = {
    "s3": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
    "ec2": ["ec2:DescribeInstances"],
    "sqs": ["sqs:SendMessage", "sqs:GetQueueAttributes"],
    "logs": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
    "dynamodb": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
    "iam": ["iam:GetUser", "iam:ListUsers"],
    "sts": ["sts:GetCallerIdentity"],
}


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _material_findings_for_statement(
    findings: list[dict[str, Any]], index: int
) -> list[dict[str, Any]]:
    return [finding for finding in findings if finding.get("statement_index") == index]


def _all_actions(statement: dict[str, Any]) -> list[str]:
    return [
        action
        for action in normalize_to_list(statement.get("Action"))
        if isinstance(action, str)
    ]


def _s3_resources(actions: list[str]) -> list[str]:
    bucket_arn = "arn:aws:s3:::REPLACE_WITH_BUCKET_NAME"
    object_arn = "arn:aws:s3:::REPLACE_WITH_BUCKET_NAME/*"

    if any(action.startswith("s3:List") for action in actions) and all(
        action.startswith("s3:List") or action.startswith("s3:GetBucket")
        for action in actions
    ):
        return [bucket_arn]

    if any(action.startswith("s3:List") for action in actions):
        return [bucket_arn, object_arn]
    return [object_arn]


def _ec2_resources(actions: list[str]) -> list[str]:
    if actions and all(is_read_only_action(action) for action in actions):
        return ["*"]
    return ["arn:aws:ec2:REGION:ACCOUNT_ID:instance/REPLACE_WITH_INSTANCE_ID"]


def _default_resources_for_service(service: str, actions: list[str]) -> list[str]:
    if service == "s3":
        return _s3_resources(actions)
    if service == "ec2":
        return _ec2_resources(actions)
    if service == "sqs":
        return ["arn:aws:sqs:REGION:ACCOUNT_ID:REPLACE_WITH_QUEUE_NAME"]
    if service == "logs":
        return ["arn:aws:logs:REGION:ACCOUNT_ID:log-group:REPLACE_WITH_LOG_GROUP:*"]
    if service == "dynamodb":
        return ["arn:aws:dynamodb:REGION:ACCOUNT_ID:table/REPLACE_WITH_TABLE_NAME"]
    if service == "iam":
        return ["arn:aws:iam::ACCOUNT_ID:user/REPLACE_WITH_USER_NAME"]
    if service == "sts":
        return ["*"]
    return ["*"]


def _best_effort_actions(
    statement: dict[str, Any], services: set[str]
) -> tuple[list[str], bool]:
    actions = _all_actions(statement)
    if actions and all(not is_action_wildcard(action) for action in actions):
        return actions, False

    replacement: list[str] = []
    for service in sorted(services):
        replacement.extend(SAFE_ACTIONS_BY_SERVICE.get(service, []))

    if not replacement:
        replacement = ["sts:GetCallerIdentity"]

    return _dedupe(replacement), True


def _best_effort_resources(
    statement: dict[str, Any],
    services: set[str],
    replacement_actions: list[str],
) -> tuple[list[str], bool]:
    current_resources = [
        resource
        for resource in normalize_to_list(statement.get("Resource"))
        if isinstance(resource, str)
    ]
    if current_resources and not any(
        is_resource_broad(resource) for resource in current_resources
    ):
        return current_resources, False

    service = sorted(services)[0] if services else "sts"
    return _default_resources_for_service(service, replacement_actions), True


def _should_add_condition(
    statement: dict[str, Any], statement_findings: list[dict[str, Any]]
) -> bool:
    if not is_allow_statement(statement) or has_condition(statement):
        return False
    return any(
        finding.get("severity") in {"CRITICAL", "HIGH"}
        for finding in statement_findings
    )


def _merge_condition(statement: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(statement)
    if not has_condition(merged):
        merged["Condition"] = copy.deepcopy(MFA_CONDITION)
    return merged


def _build_sid(services: set[str], index: int) -> str:
    if not services:
        return f"RemediatedStatement{index}"
    service = sorted(services)[0].upper()
    return f"Remediated{service}Statement{index}"


def _deterministic_remediation(
    policy: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    remediated_policy = copy.deepcopy(policy)
    changes: list[str] = []
    unresolved_intent = False

    statements = remediated_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
        remediated_policy["Statement"] = statements

    for index, statement in enumerate(statements):
        statement_findings = _material_findings_for_statement(findings, index)
        if not statement_findings or not is_allow_statement(statement):
            continue

        services = infer_services_from_statement(statement)
        replacement_actions, actions_changed = _best_effort_actions(statement, services)
        if actions_changed:
            statement["Action"] = replacement_actions
            statement.pop("NotAction", None)
            if services:
                changes.append(
                    f"Statement {index}: replaced wildcard or inverted access logic with explicit {sorted(services)[0].upper()} actions."
                )
            else:
                unresolved_intent = True
                changes.append(
                    f"Statement {index}: replaced non-specific permissions with a minimal fallback action because the original intent could not be inferred safely."
                )

        replacement_resources, resources_changed = _best_effort_resources(
            statement, services, replacement_actions
        )
        if resources_changed:
            statement["Resource"] = (
                replacement_resources
                if len(replacement_resources) > 1
                else replacement_resources[0]
            )
            changes.append(
                f"Statement {index}: scoped resources to example ARN patterns that should be replaced with real resource identifiers."
            )

        if _should_add_condition(statement, statement_findings):
            merged_statement = _merge_condition(statement)
            statement.clear()
            statement.update(merged_statement)
            changes.append(
                f"Statement {index}: added an MFA-based condition to constrain sensitive access."
            )

        if not statement.get("Sid"):
            statement["Sid"] = _build_sid(services, index)

    reasoning = (
        "The original policy included overly broad Allow permissions that exceeded least-privilege expectations. "
        "The remediated version replaces wildcard or inverted action logic with explicit actions, scopes resources to concrete ARN templates where possible, "
        "and adds MFA-based conditions to reduce abuse if credentials are compromised."
    )
    if unresolved_intent:
        reasoning += (
            " Some statements did not contain enough service context to infer their original purpose confidently, "
            "so the remediation fell back to a minimal identity lookup permission as a safe placeholder."
        )

    return {
        "remediated_policy": validate_policy_document(remediated_policy),
        "changes": changes,
        "reasoning": reasoning,
    }


def _remediate_with_gemini(
    policy: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if genai is None or not os.getenv("GEMINI_API_KEY"):
        return None

    genai.configure(api_key=os.environ["GEMINI_API_KEY"])
    model = genai.GenerativeModel(
        model_name=os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
        generation_config={"temperature": 0.3},
    )
    prompt = f"""
You are an AWS IAM security expert. Remediate the following IAM policy without changing its legitimate intent.

ORIGINAL POLICY:
{json.dumps(policy, indent=2)}

IDENTIFIED WEAKNESSES:
{json.dumps(findings, indent=2)}

Respond with JSON only in this shape:
{{
  "remediated_policy": {{ ... }},
  "changes": ["change 1", "change 2"],
  "reasoning": "security rationale"
}}

Rules:
- Preserve Sid, Principal, and Effect unless they are part of the weakness.
- Replace wildcard actions with explicit actions.
- Replace broad resources with example ARN patterns when the service supports resource scoping.
- Replace NotAction with explicit Action lists.
- Add conditions to broad Allow statements.
- Output valid IAM JSON.
""".strip()

    response = model.generate_content(prompt)
    parsed = json.loads(response.text)
    parsed["remediated_policy"] = validate_policy_document(parsed["remediated_policy"])
    return parsed


def remediate_policy(
    policy: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    try:
        gemini_result = _remediate_with_gemini(policy, findings)
        if gemini_result is not None:
            return gemini_result
    except Exception:
        pass

    return _deterministic_remediation(policy, findings)
