from __future__ import annotations

import json
from typing import Any


FINAL_ANSWER_SCHEMA = {
    "policy": "<original policy object>",
    "classification": "Weak | Strong",
    "reason": "<one-sentence summary>",
    "findings": ["<finding 1>", "<finding 2>"],
    "remediated_policy": "<optional remediated policy object>",
    "changes": ["<change 1>", "<change 2>"],
    "reasoning": "<optional security rationale>",
}


def _render_payload(payload: Any) -> str:
    if isinstance(payload, (dict, list)):
        return json.dumps(payload, indent=2, sort_keys=True)
    return str(payload)


def build_system_prompt(tool_schemas: list[dict[str, Any]]) -> str:
    return (
        "You are a senior AWS cloud security engineer specializing in IAM policy analysis.\n"
        "Use a ReAct-style loop: think about the next weakness check, call exactly one tool at a time, observe the tool result, and continue until you can classify the policy.\n"
        "Apply least privilege, avoid wildcard actions and resources in Allow statements, prefer explicit Action lists over NotAction, and require compensating conditions on broad access.\n"
        "When the policy is weak, produce a remediated version that preserves legitimate intent as closely as possible.\n\n"
        "Available tools:\n"
        f"{json.dumps(tool_schemas, indent=2)}\n\n"
        "Respond with JSON only in one of these shapes:\n"
        '{"thought": "...", "tool": "tool_name", "args": { ... }}\n'
        "or\n"
        f'{{"thought": "...", "final_answer": {json.dumps(FINAL_ANSWER_SCHEMA)}}}'
    )


def build_initial_user_message(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": "user",
        "content": "Analyze this IAM policy and classify it as Weak or Strong.",
        "policy": policy,
    }


def build_assistant_message(
    thought: str | None,
    tool_call: dict[str, Any] | None = None,
    final_answer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if thought:
        payload["thought"] = thought
    if tool_call:
        payload["tool_call"] = tool_call
    if final_answer:
        payload["final_answer"] = final_answer
    return {"role": "assistant", "content": payload}


def build_observation_message(
    tool_name: str, observation: dict[str, Any]
) -> dict[str, Any]:
    return {"role": "tool", "name": tool_name, "content": observation}


def format_for_gemini(messages: list[dict[str, Any]], system_prompt: str) -> str:
    lines = [system_prompt, "", "Conversation:"]
    for message in messages:
        role = str(message.get("role", "user")).upper()
        if role == "TOOL":
            lines.append(
                f"TOOL {message.get('name', 'unknown')}:\n{_render_payload(message.get('content'))}"
            )
            continue

        lines.append(f"{role}:\n{_render_payload(message.get('content'))}")
        if "policy" in message:
            lines.append(_render_payload(message["policy"]))
    return "\n\n".join(lines)
