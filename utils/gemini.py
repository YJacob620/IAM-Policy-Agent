"""Gemini SDK adapter utilities used by the classifier and remediation tool."""

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


def create_gemini_client(api_key: str | None = None) -> Any:
    """Create a Gemini client after verifying API key configuration."""

    resolved_api_key = api_key or os.getenv("GEMINI_API_KEY")
    if not resolved_api_key:
        raise GeminiConfigurationError(
            "Missing GEMINI_API_KEY. Configure it in the environment or .env file."
        )

    return genai.Client(api_key=resolved_api_key)


def get_gemini_model_name(model: str | None = None) -> str:
    """Resolve the Gemini model name from override, env var, or default."""

    resolved = model or os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
    return str(resolved).strip() or DEFAULT_GEMINI_MODEL


def build_generation_config(
    *,
    system_instruction: str,
    temperature: float,
    max_output_tokens: int,
    response_json_schema: dict[str, Any] | None = None,
) -> types.GenerateContentConfig:
    """Build a JSON-mode generation config with optional schema constraints."""

    config_kwargs: dict[str, Any] = {
        "system_instruction": system_instruction,
        "temperature": temperature,
        "response_mime_type": "application/json",
        "max_output_tokens": max_output_tokens,
    }
    if response_json_schema is not None:
        config_kwargs["response_json_schema"] = response_json_schema

    return types.GenerateContentConfig(**config_kwargs)


def _extract_response_text(response: Any) -> str:
    """Extract text from Gemini responses across SDK response shapes."""

    text = getattr(response, "text", None)
    if isinstance(text, str) and text.strip():
        return text

    candidates = getattr(response, "candidates", None)
    if isinstance(candidates, list):
        parts: list[str] = []
        for candidate in candidates:
            content = getattr(candidate, "content", None)
            candidate_parts = getattr(content, "parts", None)
            if not isinstance(candidate_parts, list):
                continue

            for part in candidate_parts:
                part_text = getattr(part, "text", None)
                if isinstance(part_text, str) and part_text.strip():
                    parts.append(part_text)
        if parts:
            return "\n".join(parts)

    raise GeminiResponseError("Gemini returned no textual response body.")


def _parse_response_payload(response: Any) -> dict[str, Any]:
    parsed = getattr(response, "parsed", None)
    if isinstance(parsed, dict):
        return parsed
    if hasattr(parsed, "model_dump"):
        dumped = parsed.model_dump()
        if isinstance(dumped, dict):
            return dumped

    text = _extract_response_text(response)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GeminiResponseError(
            f"Gemini returned invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno}).\nResponse text was: {text}"
        ) from exc

    if not isinstance(payload, dict):
        raise GeminiResponseError("Gemini returned JSON that was not an object.")
    return payload


def generate_json_response(
    client: Any,
    *,
    model: str,
    contents: str,
    system_instruction: str,
    temperature: float = 0.1,
    max_output_tokens: int = 1024,
    response_json_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call Gemini in JSON mode and return the parsed object payload."""

    config = build_generation_config(
        system_instruction=system_instruction,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        response_json_schema=response_json_schema,
    )

    try:
        response = client.models.generate_content(
            model=get_gemini_model_name(model),
            contents=contents,
            config=config,
        )
    except Exception as exc:
        raise GeminiResponseError(str(exc)) from exc

    return _parse_response_payload(response)
