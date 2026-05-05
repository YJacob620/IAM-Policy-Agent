from __future__ import annotations

import json

from agent.agent import ClassifyingAgent, RemediatingAgent
from agent.prompts import (
    CLASSIFICATION_RESPONSE_JSON_SCHEMA,
    REMEDIATION_RESPONSE_JSON_SCHEMA,
)
from utils.gemini import GeminiResponseError


class FakeResponse:
    def __init__(self, text: str):
        self.text = text


class FakeModels:
    def __init__(self, response_text: str):
        self.calls: list[dict[str, object]] = []
        self.response_text = response_text

    def generate_content(self, **kwargs: object) -> FakeResponse:
        self.calls.append(kwargs)
        return FakeResponse(self.response_text)


class FakeClient:
    def __init__(self, response_text: str):
        self.models = FakeModels(response_text)


class ErrorModels:
    def generate_content(self, **kwargs: object) -> FakeResponse:
        raise RuntimeError("quota exceeded")


class ErrorClient:
    def __init__(self):
        self.models = ErrorModels()


def _config_dict(config: object) -> dict[str, object]:
    if hasattr(config, "model_dump"):
        return getattr(config, "model_dump")()
    return dict(getattr(config, "__dict__", {}))


def test_classifying_agent_uses_structured_output_schema() -> None:
    fake_client = FakeClient(
        json.dumps(
            {
                "classification": "Weak",
                "reason": "Wildcard access makes this policy overly permissive.",
            }
        )
    )
    agent = ClassifyingAgent(client=fake_client, model="gemini-test")

    response = agent.classify(
        policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        },
        analysis_results={
            "check_wildcards": {
                "wildcards_found": True,
                "findings": [
                    {
                        "statement_index": 0,
                        "sid": "Statement0",
                        "action_value": "*",
                        "severity": "CRITICAL",
                        "reason": "Wildcard actions expand permissions beyond least privilege.",
                    }
                ],
            },
            "check_resource_scope": {
                "unrestricted_resources": True,
                "findings": [],
            },
        },
    )

    assert response == {
        "classification": "Weak",
        "reason": "Wildcard access makes this policy overly permissive.",
    }

    call = fake_client.models.calls[0]
    config = _config_dict(call["config"])
    assert call["model"] == "gemini-test"
    assert "Analysis Tool Output" in str(call["contents"])
    assert config["system_instruction"] == agent.system_instruction
    assert config["response_mime_type"] == "application/json"
    assert config["response_json_schema"] == CLASSIFICATION_RESPONSE_JSON_SCHEMA
    assert config["temperature"] == 0.1


def test_remediating_agent_uses_structured_output_schema() -> None:
    fake_client = FakeClient(
        json.dumps(
            {
                "remediated_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "ScopedS3Read",
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:ListBucket"],
                            "Resource": [
                                "arn:aws:s3:::example-bucket",
                                "arn:aws:s3:::example-bucket/*",
                            ],
                        }
                    ],
                },
                "changes": ["Replaced wildcard access with scoped S3 read actions."],
                "reasoning": "The policy now follows least privilege for typical S3 read access.",
            }
        )
    )
    agent = RemediatingAgent(client=fake_client, model="gemini-test")

    response = agent.remediate(
        policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        },
        relevant_analysis_results={
            "check_wildcards": {
                "wildcards_found": True,
                "findings": [{"statement_index": 0, "sid": "Statement0"}],
            }
        },
    )

    assert response["changes"] == [
        "Replaced wildcard access with scoped S3 read actions."
    ]
    assert (
        response["reasoning"]
        == "The policy now follows least privilege for typical S3 read access."
    )
    assert response["remediated_policy"]["Statement"][0]["Action"] == [
        "s3:GetObject",
        "s3:ListBucket",
    ]

    call = fake_client.models.calls[0]
    config = _config_dict(call["config"])
    assert call["model"] == "gemini-test"
    assert "Analysis Tool Output" in str(call["contents"])
    assert config["response_mime_type"] == "application/json"
    assert config["response_json_schema"] == REMEDIATION_RESPONSE_JSON_SCHEMA
    assert config["temperature"] == 0.3


def test_remediating_agent_accepts_raw_prompt_contents() -> None:
    fake_client = FakeClient(
        json.dumps(
            {
                "remediated_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": "arn:aws:s3:::example-bucket/*",
                        }
                    ],
                },
                "changes": ["Narrowed access to read-only S3 action."],
                "reasoning": "The statement was tightened to least privilege.",
            }
        )
    )
    agent = RemediatingAgent(client=fake_client, model="gemini-test")

    raw_contents = "Remediate this policy using these findings..."
    response = agent.remediate_from_contents(raw_contents)

    assert response["changes"] == ["Narrowed access to read-only S3 action."]
    assert response["reasoning"] == "The statement was tightened to least privilege."
    assert fake_client.models.calls[0]["contents"] == raw_contents


def test_classifying_agent_wraps_gemini_request_failures() -> None:
    agent = ClassifyingAgent(client=ErrorClient(), model="gemini-test")

    try:
        agent.classify(
            policy={
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            },
            analysis_results={
                "check_wildcards": {
                    "wildcards_found": True,
                    "findings": [{"statement_index": 0}],
                }
            },
        )
    except GeminiResponseError as exc:
        assert "quota exceeded" in str(exc)
    else:
        raise AssertionError(
            "Expected GeminiResponseError when the Gemini client raises."
        )
