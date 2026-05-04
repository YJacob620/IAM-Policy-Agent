from __future__ import annotations

import json
from typing import Any

from utils.gemini import (
    GeminiResponseError,
    create_gemini_client,
    generate_json_response,
    get_gemini_model_name,
)
from utils.validators import validate_policy_document


REMEDIATION_SYSTEM_INSTRUCTION = """
You are a senior AWS IAM security engineer.
Return only JSON.
Preserve the original intent of the policy as closely as possible while applying least privilege.
Replace wildcard actions with explicit actions, replace broad resources with example ARN templates when possible, replace NotAction with explicit Action lists, and add conditions when broad Allow access needs compensating controls.
The remediated policy must be valid IAM JSON.
""".strip()


def _build_remediation_prompt(
    policy: dict[str, Any], findings: list[dict[str, Any]]
) -> str:
    return f"""
Remediate the following AWS IAM policy.

ORIGINAL POLICY:
{json.dumps(policy, indent=2, sort_keys=True)}

IDENTIFIED WEAKNESSES:
{json.dumps(findings, indent=2, sort_keys=True)}

Respond with JSON only in this exact shape:
{{
  "remediated_policy": {{ ... }},
  "changes": ["change 1", "change 2"],
  "reasoning": "security rationale"
}}
""".strip()


def remediate_policy(
    policy: dict[str, Any],
    findings: list[dict[str, Any]],
    client: Any | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    gemini_client = client or create_gemini_client()
    payload = generate_json_response(
        gemini_client,
        model=get_gemini_model_name(model),
        contents=_build_remediation_prompt(policy, findings),
        system_instruction=REMEDIATION_SYSTEM_INSTRUCTION,
        temperature=0.3,
        max_output_tokens=3072,
    )

    remediated_policy = payload.get("remediated_policy")
    changes = payload.get("changes")
    reasoning = payload.get("reasoning")

    if not isinstance(remediated_policy, dict):
        raise GeminiResponseError(
            "Gemini remediation response did not include a remediated_policy object."
        )
    if not isinstance(changes, list) or not all(
        isinstance(change, str) for change in changes
    ):
        raise GeminiResponseError(
            "Gemini remediation response did not include a valid changes array."
        )
    if not isinstance(reasoning, str) or not reasoning.strip():
        raise GeminiResponseError(
            "Gemini remediation response did not include a non-empty reasoning string."
        )

    return {
        "remediated_policy": validate_policy_document(remediated_policy),
        "changes": changes,
        "reasoning": reasoning.strip(),
    }
