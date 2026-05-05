"""Prompt helpers and JSON schemas for the two-phase IAM workflow."""

from __future__ import annotations

import json
from typing import Any


CLASSIFICATION_RESPONSE_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "classification": {"type": "string", "enum": ["Weak", "Strong"]},
        "reason": {"type": "string"},
    },
    "required": ["classification", "reason"],
    "additionalProperties": False,
}


REMEDIATION_RESPONSE_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "remediated_policy": {
            "type": "object",
            "additionalProperties": True,
        },
        "changes": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
        "reasoning": {"type": "string"},
    },
    "required": ["remediated_policy", "changes", "reasoning"],
    "additionalProperties": False,
}


def build_classification_system_instruction() -> str:
    """Return the classifier-system instruction without output-shape boilerplate."""

    return (
        "You are a senior cloud security engineer. "
        "You are tasked with classifying provided AWS IAM policies as Weak or Strong, using the provided analysis tools' results. "
        "A policy is Weak when any material least-privilege issue is present, including wildcard actions, broad resources without sufficient compensation, NotAction in Allow statements, or full admin patterns. "
        "A policy is Strong only when these weaknesses are absent. "
        "Keep the reason concise and evidence-based."
    )


def build_classification_prompt(
    policy: dict[str, Any],
    analysis_results: dict[str, dict[str, Any]],
) -> str:
    """Build the single-shot classification prompt with all deterministic evidence."""

    policy_str = json.dumps(policy, indent=2, sort_keys=True)
    analysis_results_str = json.dumps(analysis_results, indent=2, sort_keys=True)

    return (
        "Classify this AWS IAM policy using the analysis tool's output.\n\n"
        "Policy:\n"
        f"{policy_str}\n\n"
        "Analysis Tool Output:\n"
        f"{analysis_results_str}\n\n"
        "Task:\n"
        "1) Determine whether the policy is Weak or Strong.\n"
        "2) Provide a short reason grounded in the analysis results."
    )


def build_remediation_system_instruction() -> str:
    """Return the remediator-system instruction without output-shape boilerplate."""

    return (
        "You are a senior cloud security engineer. "
        "You are tasked with remediating weak AWS IAM policies using the provided analysis tools' results and recommendations. "
        "Preserve policy intent where possible while enforcing least privilege. "
        "Return a valid IAM policy object and clear explanations of what changed and why."
    )


def build_remediation_prompt(
    policy: dict[str, Any],
    relevant_analysis_results: dict[str, dict[str, Any]],
) -> str:
    """Build the remediation prompt (for weak policies)."""

    return (
        "Remediate this weak AWS IAM policy while preserving its intent as much as possible. Use the analysis tool's output.\n\n"
        "Policy:\n"
        f"{json.dumps(policy, indent=2, sort_keys=True)}\n\n"
        "Analysis Tool Output:\n"
        f"{json.dumps(relevant_analysis_results, indent=2, sort_keys=True)}\n\n"
        "Task:\n"
        "1) Produce a remediated policy.\n"
        "2) List concrete changes.\n"
        "3) Explain the security reasoning."
    )
