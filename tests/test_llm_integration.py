from __future__ import annotations

import json

from agent.agent import Agent
from agent.prompts import (
    build_assistant_message,
    build_initial_user_message,
    build_observation_message,
    format_for_gemini,
)
from tools.remediation_tool import remediate_policy
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


def test_agent_uses_google_genai_generate_content_shape() -> None:
    fake_client = FakeClient(
        json.dumps(
            {
                "thought": "I should inspect wildcard actions first.",
                "tool_call": {
                    "tool_name": "check_wildcards",
                    "args": {"policy": {"Version": "2012-10-17", "Statement": []}},
                },
            }
        )
    )
    agent = Agent(client=fake_client, model="gemini-test")

    response = agent.call(
        [
            build_initial_user_message(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                }
            )
        ]
    )

    assert response.is_tool_call is True
    assert response.tool_call == {
        "tool_name": "check_wildcards",
        "args": {"policy": {"Version": "2012-10-17", "Statement": []}},
    }

    call = fake_client.models.calls[0]
    config = _config_dict(call["config"])
    assert call["model"] == "gemini-test"
    assert "Analyze this IAM policy" in str(call["contents"])
    assert config["system_instruction"] == agent.system_prompt
    assert config["response_mime_type"] == "application/json"
    assert config["temperature"] == 0.1


def test_agent_accepts_tool_alias_inside_tool_call() -> None:
    fake_client = FakeClient(
        json.dumps(
            {
                "thought": "I should inspect wildcard actions first.",
                "tool_call": {
                    "tool": "check_wildcards",
                    "args": {"policy": {"Version": "2012-10-17", "Statement": []}},
                },
            }
        )
    )
    agent = Agent(client=fake_client, model="gemini-test")

    response = agent.call(
        [
            build_initial_user_message(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                }
            )
        ]
    )

    assert response.tool_call == {
        "tool_name": "check_wildcards",
        "args": {"policy": {"Version": "2012-10-17", "Statement": []}},
    }


def test_format_for_gemini_normalizes_tool_history() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123456789012:role/DeploymentRole",
            }
        ],
    }

    prompt = format_for_gemini(
        [
            build_initial_user_message(policy),
            build_assistant_message(
                thought="I should check resource scoping next.",
                tool_call={
                    "tool": "check_resource_scope",
                    "args": {"policy": policy},
                },
            ),
            build_observation_message(
                "check_resource_scope",
                {
                    "findings": [],
                    "unrestricted_resources": False,
                },
            ),
        ]
    )

    assert '"tool_name": "check_resource_scope"' in prompt
    assert '"tool": "check_resource_scope"' not in prompt
    assert "<same policy shown in the USER Policy block>" in prompt
    assert prompt.count('"Version": "2012-10-17"') == 1
    assert "TOOL RESULT:" in prompt


def test_remediation_tool_uses_google_genai_generate_content_shape() -> None:
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
                "reasoning": "The model reduced the policy to a least-privilege S3 example.",
            }
        )
    )

    result = remediate_policy(
        policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        },
        findings=[
            {
                "statement_index": 0,
                "sid": "Statement0",
                "severity": "CRITICAL",
                "reason": "Effect:Allow combined with Action:* and Resource:* is administrator-equivalent access.",
            }
        ],
        client=fake_client,
        model="gemini-test",
    )

    assert result["changes"] == [
        "Replaced wildcard access with scoped S3 read actions."
    ]
    assert (
        result["reasoning"]
        == "The model reduced the policy to a least-privilege S3 example."
    )
    assert result["remediated_policy"]["Statement"][0]["Action"] == [
        "s3:GetObject",
        "s3:ListBucket",
    ]

    call = fake_client.models.calls[0]
    config = _config_dict(call["config"])
    assert call["model"] == "gemini-test"
    assert "IDENTIFIED WEAKNESSES" in str(call["contents"])
    assert config["response_mime_type"] == "application/json"
    assert config["temperature"] == 0.3


def test_agent_wraps_gemini_request_failures() -> None:
    agent = Agent(client=ErrorClient(), model="gemini-test")

    try:
        agent.call(
            [
                build_initial_user_message(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ],
                    }
                )
            ]
        )
    except GeminiResponseError as exc:
        assert "quota exceeded" in str(exc)
    else:
        raise AssertionError(
            "Expected GeminiResponseError when the Gemini client raises."
        )
