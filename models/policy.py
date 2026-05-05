"""Pydantic models for the supported AWS IAM policy schema."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


StringListLike = str | list[str]


def _ensure_string_list(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return value
    raise TypeError("Expected a string or list of strings.")


class StatementModel(BaseModel):
    """Strict subset of IAM statement fields accepted by this project."""

    model_config = ConfigDict(extra="forbid")

    Sid: str | None = None
    Effect: str = Field(..., pattern="^(Allow|Deny)$")
    Action: StringListLike | None = None
    NotAction: StringListLike | None = None
    Resource: StringListLike | None = None
    NotResource: StringListLike | None = None
    Condition: dict[str, Any] | None = None
    Principal: Any | None = None
    NotPrincipal: Any | None = None

    @field_validator("Action", "NotAction", "Resource", "NotResource", mode="before")
    @classmethod
    def validate_string_list_like(cls, value: Any) -> Any:
        return _ensure_string_list(value)

    @field_validator("Condition", mode="before")
    @classmethod
    def validate_condition(cls, value: Any) -> Any:
        if value is None or isinstance(value, dict):
            return value
        return None

    @model_validator(mode="after")
    def validate_action_shape(self) -> "StatementModel":
        if self.Action is None and self.NotAction is None:
            raise ValueError("Each statement must define Action or NotAction.")
        return self


class PolicyModel(BaseModel):
    """Validated top-level IAM policy document used by the runtime."""

    model_config = ConfigDict(extra="forbid")

    Id: str | None = None
    Version: str = "2012-10-17"
    Statement: list[StatementModel]

    @field_validator("Statement", mode="before")
    @classmethod
    def normalize_statement_list(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return [value]
        return value
