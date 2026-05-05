from __future__ import annotations

from typing import Any

from agent.orchestrator import Orchestrator


class StubClassifier:
    def __init__(self, response: dict[str, str]):
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def classify(
        self,
        policy: dict[str, Any],
        analysis_results: dict[str, dict[str, Any]],
    ) -> dict[str, str]:
        self.calls.append(
            {
                "policy": policy,
                "analysis_results": analysis_results,
            }
        )
        return dict(self.response)


class StubRemediator:
    def __init__(self, response: dict[str, Any]):
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def remediate(
        self,
        policy: dict[str, Any],
        relevant_analysis_results: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "policy": policy,
                "relevant_analysis_results": relevant_analysis_results,
            }
        )
        return dict(self.response)


def test_orchestrator_runs_all_tools_and_remediator_for_weak_policy() -> None:
    weak_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    classifier = StubClassifier(
        {
            "classification": "Weak",
            "reason": "Wildcard and full-admin patterns were detected.",
        }
    )
    remediator = StubRemediator(
        {
            "remediated_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ScopedS3Read",
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "arn:aws:s3:::example-bucket/*",
                    }
                ],
            },
            "changes": ["Replaced wildcard admin access with scoped S3 read."],
            "reasoning": "The remediated policy removes unrestricted permissions.",
        }
    )

    result = Orchestrator(
        classifying_agent=classifier,
        remediating_agent=remediator,
    ).run(weak_policy)

    assert result.classification == "Weak"
    assert result.reason == "Wildcard and full-admin patterns were detected."
    assert len(classifier.calls) == 1

    analysis_results = classifier.calls[0]["analysis_results"]
    assert set(analysis_results) == {
        "check_wildcards",
        "check_resource_scope",
        "check_conditions",
        "check_effect_allow_star",
    }

    assert len(remediator.calls) == 1
    remediation_call = remediator.calls[0]
    assert set(remediation_call["relevant_analysis_results"]) == {
        "check_wildcards",
        "check_resource_scope",
        "check_conditions",
        "check_effect_allow_star",
    }

    assert result.remediated_policy is not None
    assert result.changes == ["Replaced wildcard admin access with scoped S3 read."]


def test_orchestrator_skips_remediation_for_strong_policy() -> None:
    strong_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }
    classifier = StubClassifier(
        {
            "classification": "Strong",
            "reason": "No material least-privilege weakness was found.",
        }
    )
    remediator = StubRemediator(
        {
            "remediated_policy": strong_policy,
            "changes": ["No-op"],
            "reasoning": "Not expected to be called.",
        }
    )

    result = Orchestrator(
        classifying_agent=classifier,
        remediating_agent=remediator,
    ).run(strong_policy)

    assert result.classification == "Strong"
    assert result.remediated_policy is None
    assert result.changes == []
    assert remediator.calls == []
