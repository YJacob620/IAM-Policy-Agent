"""Gemini-backed agents for classification and remediation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent.prompts import (
    CLASSIFICATION_RESPONSE_JSON_SCHEMA,
    REMEDIATION_RESPONSE_JSON_SCHEMA,
    build_classification_prompt,
    build_classification_system_instruction,
    build_remediation_prompt,
    build_remediation_system_instruction,
)
from utils.gemini import (
    create_gemini_client,
    generate_json_response,
    get_gemini_model_name,
)
from utils.validators import validate_policy_document


class ClassificationPayload(BaseModel):
    """Schema returned by the classification agent."""

    model_config = ConfigDict(extra="forbid")

    classification: Literal["Weak", "Strong"]
    reason: str = Field(..., min_length=1)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        return value.strip()


class RemediationPayload(BaseModel):
    """Schema returned by the remediation agent."""

    model_config = ConfigDict(extra="forbid")

    remediated_policy: dict[str, Any]
    changes: list[str] = Field(default_factory=list, min_length=1)
    reasoning: str = Field(..., min_length=1)

    @field_validator("changes")
    @classmethod
    def normalize_changes(cls, value: list[str]) -> list[str]:
        cleaned = [
            item.strip() for item in value if isinstance(item, str) and item.strip()
        ]
        if not cleaned:
            raise ValueError("changes must contain at least one non-empty item.")
        return cleaned

    @field_validator("reasoning")
    @classmethod
    def normalize_reasoning(cls, value: str) -> str:
        return value.strip()


class ClassifyingAgent:
    """Classify IAM policies using deterministic tool evidence."""

    def __init__(self, client: Any | None = None, model: str | None = None):
        self.client = client or create_gemini_client()
        self.model = get_gemini_model_name(model)
        self.system_instruction = build_classification_system_instruction()

    def classify(
        self,
        policy: dict[str, Any],
        analysis_results: dict[str, dict[str, Any]],
    ) -> dict[str, str]:
        payload = generate_json_response(
            self.client,
            model=self.model,
            contents=build_classification_prompt(policy, analysis_results),
            system_instruction=self.system_instruction,
            temperature=0.1,
            max_output_tokens=5000,
            response_json_schema=CLASSIFICATION_RESPONSE_JSON_SCHEMA,
        )
        parsed = ClassificationPayload.model_validate(payload)
        return {
            "classification": parsed.classification,
            "reason": parsed.reason,
        }


class RemediatingAgent:
    """Generate remediated IAM policies for weak classifications."""

    def __init__(self, client: Any | None = None, model: str | None = None):
        self.client = client or create_gemini_client()
        self.model = get_gemini_model_name(model)
        self.system_instruction = build_remediation_system_instruction()

    def _run_remediation_request(self, contents: str) -> dict[str, Any]:
        if not isinstance(contents, str) or not contents.strip():
            raise ValueError("Remediation prompt contents must be a non-empty string.")

        payload = generate_json_response(
            self.client,
            model=self.model,
            contents=contents,
            system_instruction=self.system_instruction,
            temperature=0.3,
            max_output_tokens=20000,
            response_json_schema=REMEDIATION_RESPONSE_JSON_SCHEMA,
        )
        parsed = RemediationPayload.model_validate(payload)
        validated_policy = validate_policy_document(parsed.remediated_policy)
        return {
            "remediated_policy": validated_policy,
            "changes": parsed.changes,
            "reasoning": parsed.reasoning,
        }

    def remediate(
        self,
        policy: dict[str, Any],
        relevant_analysis_results: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        return self._run_remediation_request(
            build_remediation_prompt(
                policy,
                relevant_analysis_results,
            )
        )

    def remediate_from_contents(self, contents: str) -> dict[str, Any]:
        """Run remediation from a fully prepared prompt loaded from disk."""

        return self._run_remediation_request(contents)
