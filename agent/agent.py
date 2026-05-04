from __future__ import annotations
import json
import os
from dataclasses import dataclass
from typing import Any
from agent.prompts import build_system_prompt, format_for_gemini
from tools.registry import TOOL_SCHEMAS
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

MATERIAL_SEVERITIES = {"HIGH", "CRITICAL"}


@dataclass(slots=True)
class AgentResponse:
    thought: str | None = None
    tool_call: dict[str, Any] | None = None
    final_answer: dict[str, Any] | None = None

    @property
    def is_tool_call(self) -> bool:
        return self.tool_call is not None

    @property
    def is_final_answer(self) -> bool:
        return self.final_answer is not None


class Agent:
    TOOL_SEQUENCE = (
        (
            "check_effect_allow_star",
            "I need to check for the highest-severity administrator-equivalent pattern first.",
        ),
        (
            "check_wildcards",
            "Next I should inspect wildcard actions to understand how broad the allowed permissions are.",
        ),
        (
            "check_not_actions",
            "I should also verify that the policy does not invert its allow-list with NotAction.",
        ),
        (
            "check_resource_scope",
            "Now I need to inspect whether the policy is scoped to specific resources.",
        ),
        (
            "check_conditions",
            "Finally I need to verify whether broad Allow permissions are constrained by conditions.",
        ),
    )

    def __init__(self, prefer_live_model: bool = True):
        self.system_prompt = build_system_prompt(TOOL_SCHEMAS)
        self.prefer_live_model = prefer_live_model
        self.tool_names = {schema["name"] for schema in TOOL_SCHEMAS}
        # The client gets the API key from the environment variable `GEMINI_API_KEY`.
        self.client = genai.Client()
        self.model = os.getenv("GEMINI_MODEL")
        self.config = types.GenerateContentConfig(temperature=0.1)
        print("tst")

    def call(self, messages: list[dict[str, Any]]) -> AgentResponse:
        if self.model is not None:
            try:
                return self._call_gemini(messages)
            except Exception:
                pass
        print(
            "Error calling Gemini model, falling back to deterministic agent:",
        )
        return self._call_deterministic(messages)

    def _call_gemini(self, messages: list[dict[str, Any]]) -> AgentResponse:
        prompt = format_for_gemini(messages, self.system_prompt)
        response = self.client.models.generate_content(
            model=self.model, config=self.config, prompt=prompt
        )
        payload = self._parse_json_text(response.text)

        if "final_answer" in payload:
            return AgentResponse(
                thought=payload.get("thought"), final_answer=payload["final_answer"]
            )

        tool = payload.get("tool")
        if tool not in self.tool_names:
            raise ValueError(f"Unknown tool returned by model: {tool}")

        args = payload.get("args", {})
        return AgentResponse(
            thought=payload.get("thought"), tool_call={"tool": tool, "args": args}
        )

    def _call_deterministic(self, messages: list[dict[str, Any]]) -> AgentResponse:
        policy = self._extract_policy(messages)
        observations = self._observations_by_tool(messages)

        for tool_name, thought in self.TOOL_SEQUENCE:
            if tool_name not in observations:
                return AgentResponse(
                    thought=thought,
                    tool_call={"tool": tool_name, "args": {"policy": policy}},
                )

        material_findings = self._material_findings(observations)
        if material_findings and "remediate_policy" not in observations:
            return AgentResponse(
                thought="I have enough evidence to classify this policy as weak and generate a remediation.",
                tool_call={
                    "tool": "remediate_policy",
                    "args": {"policy": policy, "findings": material_findings},
                },
            )

        return AgentResponse(
            thought="I have enough evidence to return the final classification.",
            final_answer=self._build_final_answer(policy, observations),
        )

    def _extract_policy(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        for message in messages:
            if "policy" in message:
                return message["policy"]
        raise ValueError("No policy found in the conversation history.")

    def _observations_by_tool(
        self, messages: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        observations: dict[str, dict[str, Any]] = {}
        for message in messages:
            if message.get("role") == "tool":
                observations[str(message.get("name"))] = dict(
                    message.get("content", {})
                )
        return observations

    def _material_findings(
        self, observations: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for tool_name, observation in observations.items():
            if tool_name == "remediate_policy":
                continue
            for finding in observation.get("findings", []):
                if finding.get("severity") in MATERIAL_SEVERITIES:
                    findings.append(finding)
        return findings

    def _format_finding(self, finding: dict[str, Any]) -> str:
        prefix = f"Statement {finding.get('statement_index', '?')} ({finding.get('sid', 'UnknownSid')})"
        if "action_value" in finding:
            detail = f"Action '{finding['action_value']}' uses a wildcard pattern"
        elif "resource_values" in finding:
            detail = f"Resource scope is broad: {', '.join(finding['resource_values'])}"
        elif "not_action_values" in finding:
            detail = f"NotAction is used with Allow: {', '.join(finding['not_action_values'])}"
        else:
            detail = str(finding.get("reason", "Policy weakness detected"))
        return f"{prefix}: {detail} ({finding.get('severity', 'UNKNOWN')})"

    def _build_reason(
        self, classification: str, material_findings: list[dict[str, Any]]
    ) -> str:
        if classification == "Strong":
            return (
                "No high-risk IAM weaknesses were detected in the evaluated statements."
            )
        if any(
            finding.get("reason", "").startswith("Effect:Allow combined")
            for finding in material_findings
        ):
            return "This policy grants administrator-equivalent or otherwise overly broad Allow permissions."
        return "This policy contains overly broad Allow permissions that violate least-privilege principles."

    def _build_reasoning(
        self, classification: str, material_findings: list[dict[str, Any]]
    ) -> str:
        if classification == "Strong":
            return "The evaluated statements avoid high-risk wildcard and inverted-logic patterns, and any broad scope that remains is bounded by conditions or non-Allow semantics."
        return (
            "The evaluated Allow statements include one or more broad permission patterns such as wildcard actions, unrestricted resources, missing compensating conditions, or NotAction usage. "
            "Together these findings indicate that the policy grants more access than is necessary for least privilege."
        )

    def _build_final_answer(
        self,
        policy: dict[str, Any],
        observations: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        material_findings = self._material_findings(observations)
        classification = "Weak" if material_findings else "Strong"
        remediation = (
            observations.get("remediate_policy", {}) if classification == "Weak" else {}
        )

        return {
            "policy": policy,
            "classification": classification,
            "reason": self._build_reason(classification, material_findings),
            "findings": [
                self._format_finding(finding) for finding in material_findings
            ],
            "remediated_policy": remediation.get("remediated_policy"),
            "changes": remediation.get("changes", []),
            "reasoning": remediation.get("reasoning")
            or self._build_reasoning(classification, material_findings),
        }

    @staticmethod
    def _parse_json_text(raw_text: str) -> dict[str, Any]:
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        return json.loads(text)
