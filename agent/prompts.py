from __future__ import annotations

import json
from typing import Any


FINAL_ANSWER_SCHEMA = {
    "policy": "<the original policy object exactly as provided — a JSON object, not a string>",
    "classification": "Weak | Strong",
    "reason": "<one-sentence summary explaining why the policy is Weak or Strong>",
    "findings": ["<specific security finding 1>", "<specific security finding 2>"],
    "remediated_policy": "<the fixed policy object if classification is Weak; omit or set to null if Strong>",
    "changes": [
        "<description of change made during remediation 1>",
        "<description of change 2>",
    ],
    "reasoning": "<security rationale for every remediation change; omit if Strong>",
}


def _render_payload(payload: Any) -> str:
    if isinstance(payload, (dict, list)):
        return json.dumps(payload, indent=2)
    return str(payload)


def _normalize_tool_call(tool_call: Any) -> dict[str, Any] | None:
    if not isinstance(tool_call, dict):
        return None

    tool_name = tool_call.get("tool_name") or tool_call.get("tool")
    args = tool_call.get("args", {})

    normalized: dict[str, Any] = {}
    if isinstance(tool_name, str) and tool_name:
        normalized["tool_name"] = tool_name

    if isinstance(args, dict):
        display_args = dict(args)
        if "policy" in display_args:
            display_args["policy"] = "<same policy shown in the USER Policy block>"
        normalized["args"] = display_args
    elif "args" in tool_call:
        normalized["args"] = args

    return normalized or dict(tool_call)


def _render_assistant_content(content: Any) -> str:
    if not isinstance(content, dict):
        return _render_payload(content)

    rendered_content = dict(content)
    normalized_tool_call = _normalize_tool_call(rendered_content.get("tool_call"))
    if normalized_tool_call is not None:
        rendered_content["tool_call"] = normalized_tool_call

    return _render_payload(rendered_content)


def build_system_prompt(tool_schemas: list[dict[str, Any]]) -> str:
    tool_names = [s["name"] for s in tool_schemas]
    return (
        "You are a senior AWS cloud security engineer specializing in IAM policy analysis.\n\n"
        "## Task\n"
        "Analyze the IAM policy provided by the user. Classify it as 'Weak' or 'Strong'.\n\n"
        "## Step-by-Step Workflow\n"
        "Follow this loop exactly:\n"
        "1. Think about which security property to check next.\n"
        "2. Call exactly ONE analysis tool, passing the full policy document as the 'policy' argument.\n"
        "3. Read the tool result (observation).\n"
        "4. Repeat steps 1-3 until you have checked all relevant properties.\n"
        "5. If the policy is Weak, call `remediate_policy` with the findings collected so far.\n"
        "6. Emit your final_answer.\n\n"
        "## Security Classification Rules\n"
        "A policy is Weak if ANY of the following are true:\n"
        "- An Allow statement uses a wildcard Action such as '*' or 'service:*'.\n"
        "- An Allow statement uses Resource '*' without a compensating Condition.\n"
        "- An Allow statement uses NotAction (implicitly grants everything except the listed actions).\n"
        "- An Allow statement combines Action '*' with Resource '*' (full admin — always critical).\n"
        "A policy is Strong only if none of the above weaknesses are found.\n\n"
        f"## Available Tools\n"
        f"The valid tool_name values are: {json.dumps(tool_names)}\n\n"
        f"{json.dumps(tool_schemas, indent=2)}\n\n"
        "## Response Format — STRICT\n"
        "Every response MUST be valid JSON in EXACTLY ONE of the following two shapes.\n"
        "Do NOT deviate from these shapes.\n\n"
        "Shape 1 — Tool Call (use when you need to invoke a tool):\n"
        '{"thought": "<your step-by-step reasoning>", "tool_call": {"tool_name": "<exact name from the valid tool_name values list>", "args": {"policy": <the full policy object as a JSON object, not a string>}}}\n\n'
        "Shape 2 — Final Answer (use ONLY when you are ready to classify the policy):\n"
        f'{{"thought": "<your step-by-step reasoning>", "final_answer": {json.dumps(FINAL_ANSWER_SCHEMA)}}}\n\n'
        "## Hard Rules\n"
        "- NEVER emit a response that contains both 'tool_call' and 'final_answer'.\n"
        "- NEVER emit a response that contains neither 'tool_call' nor 'final_answer'.\n"
        "- ALWAYS include the 'thought' field in every response.\n"
        "- Inside 'tool_call', ALWAYS use the key 'tool_name'. NEVER use the key 'tool'.\n"
        "- NEVER call 'remediate_policy' on a Strong policy.\n"
        "- The 'policy' argument passed to every tool MUST be the complete IAM policy JSON object "
        "from the user message — pass it as an object, not as a stringified JSON.\n"
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
        payload["tool_call"] = _normalize_tool_call(tool_call) or tool_call
    if final_answer:
        payload["final_answer"] = final_answer
    return {"role": "assistant", "content": payload}


def build_observation_message(
    tool_name: str, observation: dict[str, Any]
) -> dict[str, Any]:
    return {"role": "tool", "name": tool_name, "content": observation}


def format_for_gemini(messages: list[dict[str, Any]]) -> str:
    lines = ["Conversation:"]
    for message in messages:
        role = str(message.get("role", "user")).upper()
        if role == "TOOL":
            lines.append(
                "TOOL RESULT:\n"
                + _render_payload(
                    {
                        "tool_name": message.get("name", "unknown"),
                        "observation": message.get("content"),
                    }
                )
            )
            continue

        if role == "ASSISTANT":
            lines.append(
                f"{role}:\n{_render_assistant_content(message.get('content'))}"
            )
        else:
            lines.append(f"{role}:\n{_render_payload(message.get('content'))}")
        if "policy" in message:
            lines.append("Policy:\n" + _render_payload(message["policy"]))
    return "\n\n".join(lines)
