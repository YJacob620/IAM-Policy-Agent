from __future__ import annotations

from agent.agent import AgentResponse
from agent.orchestrator import Orchestrator


class SequenceAgent:
    def __init__(self, responses: list[AgentResponse]):
        self._responses = iter(responses)
        self.calls: list[list[dict[str, object]]] = []

    def call(self, messages: list[dict[str, object]]) -> AgentResponse:
        self.calls.append(list(messages))
        return next(self._responses)


def test_orchestrator_executes_llm_driven_tool_loop() -> None:
    normalized_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    sequence_agent = SequenceAgent(
        [
            AgentResponse(
                thought="I need evidence from the wildcard tool before deciding.",
                tool_call={
                    "tool": "check_wildcards",
                    "args": {"policy": normalized_policy},
                },
            ),
            AgentResponse(
                thought="The model has enough evidence to classify the policy.",
                final_answer={
                    "classification": "Weak",
                    "reason": "The model found unrestricted wildcard access.",
                    "findings": [
                        "Statement 0 (Statement0): Action '*' uses a wildcard pattern (CRITICAL)"
                    ],
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
                    "changes": ["Replaced wildcard access with scoped S3 read access."],
                    "reasoning": "The model reduced the permissions to a least-privilege example.",
                },
            ),
        ]
    )

    result = Orchestrator(agent=sequence_agent).run({"policy": normalized_policy})

    assert result.classification == "Weak"
    assert result.reason == "The model found unrestricted wildcard access."
    assert result.changes == ["Replaced wildcard access with scoped S3 read access."]
    assert len(sequence_agent.calls) == 2
    assert sequence_agent.calls[1][-1]["role"] == "tool"
