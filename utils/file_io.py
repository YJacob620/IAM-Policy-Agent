from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from models.output import OutputModel
from utils.validators import unwrap_policy_payload, validate_policy_document


class PolicyInputError(Exception):
    """Raised when an input policy file cannot pass preflight validation."""


class JsonFormattingError(PolicyInputError):
    """Raised when the policy file is not valid JSON."""


class IamPolicyValidationError(PolicyInputError):
    """Raised when the parsed JSON is not a valid IAM policy document."""


def _format_error_location(location: tuple[Any, ...]) -> str:
    if not location:
        return "policy root"

    formatted_parts: list[str] = []
    for item in location:
        if isinstance(item, int):
            if not formatted_parts:
                formatted_parts.append(f"[{item}]")
            else:
                formatted_parts[-1] = f"{formatted_parts[-1]}[{item}]"
            continue
        formatted_parts.append(str(item))

    return ".".join(formatted_parts)


def _format_validation_error(exc: ValidationError) -> str:
    messages: list[str] = []
    for error in exc.errors():
        location = _format_error_location(tuple(error.get("loc", ())))
        error_type = error.get("type")

        if error_type == "missing":
            attribute = str(error.get("loc", ["unknown"])[-1])
            messages.append(f"Missing required IAM attribute '{attribute}'.")
            continue

        if error_type == "extra_forbidden":
            attribute = str(error.get("loc", ["unknown"])[-1])
            parent_location = _format_error_location(tuple(error.get("loc", ())[:-1]))
            parent_message = (
                parent_location if parent_location != "policy root" else "policy root"
            )
            messages.append(
                f"Unsupported IAM attribute '{attribute}' at {parent_message}."
            )
            continue

        messages.append(f"{location}: {error.get('msg', 'Invalid IAM policy value.')}")

    return " ".join(messages)


def load_json(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyInputError(f"Policy file was not found: {file_path}") from exc
    except json.JSONDecodeError as exc:
        raise JsonFormattingError(
            f"Invalid JSON formatting in '{file_path}': {exc.msg} (line {exc.lineno}, column {exc.colno})."
        ) from exc


def load_policy(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    raw = load_json(file_path)
    try:
        return validate_policy_document(unwrap_policy_payload(raw))
    except ValidationError as exc:
        raise IamPolicyValidationError(
            f"Invalid AWS IAM policy in '{file_path}': {_format_validation_error(exc)}"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise IamPolicyValidationError(
            f"Invalid AWS IAM policy in '{file_path}': {exc}"
        ) from exc


def save_json(path: str | Path, payload: dict[str, Any]) -> Path:
    output_path = Path(path)
    output_path.write_text(json.dumps(payload, indent=4) + "\n", encoding="utf-8")
    return output_path


def save_output(
    result: OutputModel, output_dir: str | Path, source_path: str | Path
) -> dict[str, Path | None]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    stem = Path(source_path).stem
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    classification_path = save_json(
        output_path / f"{stem}_classification_{timestamp}.json",
        result.to_classification_dict(),
    )

    remediated_path: Path | None = None
    if result.classification.lower() == "weak" and result.remediated_policy is not None:
        remediated_path = save_json(
            output_path / f"{stem}_remediated_{timestamp}.json",
            result.to_remediated_dict(),
        )

    return {
        "classification_path": classification_path,
        "remediated_path": remediated_path,
    }
