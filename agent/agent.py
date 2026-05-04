from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent.prompts import build_system_prompt, format_for_gemini
from tools.registry import TOOL_SCHEMAS
from utils.gemini import (
    GeminiResponseError,
    create_gemini_client,
    generate_json_response,
    get_gemini_model_name,
)


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
    def __init__(self, client: Any | None = None, model: str | None = None):
        self.system_prompt = build_system_prompt(TOOL_SCHEMAS)
        self.tool_names = {schema["name"] for schema in TOOL_SCHEMAS}
        self.client = client or create_gemini_client()
        self.model = get_gemini_model_name(model)

    def call(self, messages: list[dict[str, Any]]) -> AgentResponse:
        prompt = format_for_gemini(messages)
        payload = generate_json_response(
            self.client,
            model=self.model,
            contents=prompt,
            system_instruction=self.system_prompt,
            temperature=0.1,
            max_output_tokens=2048,
        )

        if "final_answer" in payload:
            final_answer = payload["final_answer"]
            if not isinstance(final_answer, dict):
                raise GeminiResponseError(
                    "Gemini returned a non-object final_answer payload."
                )
            return AgentResponse(
                thought=payload.get("thought"),
                final_answer=final_answer,
            )

        tool_call_payload = payload.get("tool_call")
        if not isinstance(tool_call_payload, dict):
            tool_call_payload = {
                "tool_name": payload.get("tool"),
                "args": payload.get("args", {}),
            }

        tool_name = tool_call_payload.get("tool_name") or tool_call_payload.get("tool")
        if not isinstance(tool_name, str) or tool_name not in self.tool_names:
            raise GeminiResponseError(
                f"Gemini returned an unknown or invalid tool name: {tool_name!r}."
            )

        args = tool_call_payload.get("args", {})
        if not isinstance(args, dict):
            raise GeminiResponseError("Gemini returned non-object tool arguments.")

        return AgentResponse(
            thought=payload.get("thought"),
            tool_call={"tool_name": tool_name, "args": args},
        )
