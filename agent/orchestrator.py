"""Orchestration layer for deterministic analysis plus two Gemini phases."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from agent.agent import ClassifyingAgent, RemediatingAgent
from models.output import OutputModel
from tools.analysis_tools import run_all_analysis_tools


def _summarize_finding(finding: dict[str, Any]) -> str:
    if "action_value" in finding:
        return f"Action '{finding['action_value']}' uses a wildcard pattern"

    if "resource_values" in finding and isinstance(finding["resource_values"], list):
        resources = ", ".join(str(value) for value in finding["resource_values"])
        return f"Resource scope is broad: {resources}"

    if "not_action_values" in finding and isinstance(
        finding["not_action_values"], list
    ):
        values = ", ".join(str(value) for value in finding["not_action_values"])
        return f"NotAction is used: {values}"

    reason = finding.get("reason")
    if isinstance(reason, str) and reason.strip():
        return reason.strip()

    return "Potentially risky IAM statement."


def _collect_findings(analysis_results: dict[str, dict[str, Any]]) -> list[str]:
    findings: list[str] = []

    if isinstance(analysis_results, str):
        return findings

    for result in analysis_results.values():
        tool_findings = result.get("findings", [])
        if not isinstance(tool_findings, list):
            continue

        for raw_finding in tool_findings:
            if not isinstance(raw_finding, dict):
                continue

            statement_index = raw_finding.get("statement_index", "unknown")
            sid = raw_finding.get("sid", f"Statement{statement_index}")
            severity = raw_finding.get("severity")
            message = _summarize_finding(raw_finding)
            if isinstance(severity, str) and severity.strip():
                message = f"{message} ({severity.strip().upper()})"
            findings.append(f"Statement {statement_index} ({sid}): {message}")

    return findings


def _normalize_classification(value: Any) -> str:
    if not isinstance(value, str):
        raise RuntimeError("Classifier returned a non-string classification value.")

    normalized = value.strip().capitalize()
    if normalized not in {"Weak", "Strong"}:
        raise RuntimeError(
            "Classifier returned an invalid classification. Expected 'Weak' or 'Strong'."
        )
    return normalized


class Orchestrator:
    """Coordinate validation, deterministic analysis, classification, and remediation."""

    def __init__(
        self,
        verbose: bool = False,
        classifying_agent: ClassifyingAgent | None = None,
        remediating_agent: RemediatingAgent | None = None,
    ):
        self.classifier = classifying_agent or ClassifyingAgent()
        self._remediator = remediating_agent
        self.verbose = verbose
        self.console = Console()
        self._last_analysis_results: dict[str, dict[str, Any]] | None = None

    def _get_remediator(self) -> RemediatingAgent:
        if self._remediator is None:
            self._remediator = RemediatingAgent()
        return self._remediator

    def classify(self, policy: dict[str, Any]) -> OutputModel:
        """Run all analysis tools and classify the policy. Saves no artifacts."""

        analysis_results = run_all_analysis_tools(policy)
        self._last_analysis_results = analysis_results

        if self.verbose:
            self.console.print(
                "[yellow][Analysis][/yellow] Ran all deterministic tools."
            )
            self.console.print(json.dumps(analysis_results, indent=2, sort_keys=True))

        classification_result = self.classifier.classify(policy, analysis_results)
        classification = _normalize_classification(
            classification_result.get("classification")
        )
        reason = classification_result.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise RuntimeError("Classifier returned an empty reason.")
        reason = reason.strip()

        if self.verbose:
            self.console.print(
                f"[bold cyan][Classification][/bold cyan] {classification}: {reason}"
            )

        return OutputModel.model_validate(
            {
                "policy": policy,
                "classification": classification,
                "reason": reason,
                "findings": _collect_findings(analysis_results),
            }
        )

    def remediate(self, classification_model: OutputModel) -> OutputModel:
        """Enrich a weak classification result with a remediated policy.

        Must be called after ``classify()`` so that analysis results are available.
        Raises ``RuntimeError`` when called before ``classify()`` or on a Strong policy.
        """

        if self._last_analysis_results is None:
            raise RuntimeError("remediate() must be called after classify().")
        if classification_model.classification.lower() != "weak":
            raise RuntimeError("remediate() must only be called for Weak policies.")

        remediation_result = self._get_remediator().remediate(
            classification_model.policy,
            self._last_analysis_results,
        )

        if self.verbose:
            self.console.print("[bold magenta][Remediation][/bold magenta] Done.")

        return classification_model.model_copy(update=remediation_result)

    def run(self, policy: dict[str, Any]) -> OutputModel:
        """Run the full pipeline in a single call (classification + optional remediation)."""

        classification_model = self.classify(policy)
        if classification_model.classification == "Weak":
            return self.remediate(classification_model)
        return classification_model
