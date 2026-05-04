from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from agent.agent import Agent
from agent.prompts import (
    build_assistant_message,
    build_initial_user_message,
    build_observation_message,
)
from models.output import OutputModel
from tools.registry import dispatch_tool
from utils.validators import unwrap_policy_payload, validate_policy_document


class Orchestrator:
    def __init__(
        self,
        verbose: bool = False,
        max_iterations: int = 10,
        prefer_live_model: bool = True,
        agent: Agent | None = None,
    ):
        self.agent = agent or Agent(prefer_live_model=prefer_live_model)
        self.verbose = verbose
        self.max_iterations = max_iterations
        self.console = Console()

    def run(self, policy: dict[str, Any]) -> OutputModel:
        normalized_policy = validate_policy_document(
            unwrap_policy_payload(policy) if "policy" in policy else policy
        )
        messages: list[dict[str, Any]] = [build_initial_user_message(normalized_policy)]

        for _ in range(self.max_iterations):
            response = self.agent.call(messages)
            messages.append(
                build_assistant_message(
                    thought=response.thought,
                    tool_call=response.tool_call,
                    final_answer=response.final_answer,
                )
            )

            if self.verbose and response.thought:
                self.console.print(
                    f"[bold cyan][Agent THOUGHT][/bold cyan] {response.thought}"
                )

            if response.is_final_answer:
                payload = dict(response.final_answer or {})
                payload.setdefault("policy", normalized_policy)
                return OutputModel.model_validate(payload)

            if not response.is_tool_call:
                raise RuntimeError(
                    "Agent returned neither a tool call nor a final answer."
                )

            tool_name = str(response.tool_call["tool"])
            tool_args = dict(response.tool_call.get("args", {}))
            if self.verbose:
                display_args = {
                    key: ("<policy>" if key == "policy" else value)
                    for key, value in tool_args.items()
                }
                self.console.print(
                    f"[yellow][Tool Call][/yellow] {tool_name}({display_args})"
                )

            observation = dispatch_tool(tool_name, **tool_args)
            if self.verbose:
                self.console.print(
                    "[green][Observation][/green] "
                    + json.dumps(observation, indent=2, sort_keys=True)
                )

            messages.append(build_observation_message(tool_name, observation))

        raise RuntimeError(
            "Agent did not converge within the configured iteration limit."
        )
