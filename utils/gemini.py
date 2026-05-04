from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import types


load_dotenv()

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


class GeminiError(RuntimeError):
    """Base error for Gemini client and response failures."""


class GeminiConfigurationError(GeminiError):
    """Raised when Gemini is not configured for this workspace."""


class GeminiResponseError(GeminiError):
    """Raised when Gemini returns an unusable response."""


def create_gemini_client(api_key: str | None = None) -> genai.Client:
    resolved_api_key = api_key or os.getenv("GEMINI_API_KEY")
    if not resolved_api_key:
        raise GeminiConfigurationError(
            "GEMINI_API_KEY is not set. This program requires Gemini for policy classification and remediation."
        )
    return genai.Client(api_key=resolved_api_key)


def get_gemini_model_name(model: str | None = None) -> str:
    return model or os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL


def build_generation_config(
    *,
    system_instruction: str,
    temperature: float,
    max_output_tokens: int,
) -> types.GenerateContentConfig:
    return types.GenerateContentConfig(
        system_instruction=system_instruction,
        temperature=temperature,
        response_mime_type="application/json",
        max_output_tokens=max_output_tokens,
    )


def extract_response_text(response: Any) -> str:
    response_text = getattr(response, "text", None)
    if isinstance(response_text, str) and response_text.strip():
        return response_text

    prompt_feedback = getattr(response, "prompt_feedback", None)
    block_reason = getattr(prompt_feedback, "block_reason", None)
    if block_reason:
        raise GeminiResponseError(f"Gemini blocked the request: {block_reason}.")

    candidates = getattr(response, "candidates", None) or []
    if candidates:
        candidate = candidates[0]
        finish_reason = getattr(candidate, "finish_reason", None)
        finish_message = getattr(candidate, "finish_message", None)
        details = " ".join(
            part
            for part in [
                f"finish_reason={finish_reason}" if finish_reason else None,
                str(finish_message) if finish_message else None,
            ]
            if part
        )
        if details:
            raise GeminiResponseError(f"Gemini returned no text payload ({details}).")

    raise GeminiResponseError("Gemini returned no text payload.")


def parse_json_response(raw_text: str) -> dict[str, Any]:
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GeminiResponseError(
            f"Gemini returned invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})."
        ) from exc

    if not isinstance(parsed, dict):
        raise GeminiResponseError("Gemini returned JSON that is not an object.")
    return parsed


def generate_json_response(
    client: Any,
    *,
    model: str,
    contents: str,
    system_instruction: str,
    temperature: float,
    max_output_tokens: int,
) -> dict[str, Any]:
    try:
        response = client.models.generate_content(
            model=model,
            contents=contents,
            config=build_generation_config(
                system_instruction=system_instruction,
                temperature=temperature,
                max_output_tokens=max_output_tokens,
            ),
        )
    except Exception as exc:
        raise GeminiResponseError(str(exc)) from exc

    return parse_json_response(extract_response_text(response))
