from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from rich.table import Table


class OutputModel(BaseModel):
    policy: dict[str, Any]
    classification: str
    reason: str
    findings: list[str] = Field(default_factory=list)
    remediated_policy: dict[str, Any] | None = None
    changes: list[str] = Field(default_factory=list)
    reasoning: str | None = None

    def to_classification_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "classification": self.classification,
            "reason": self.reason,
            "findings": self.findings,
        }

    def to_remediated_dict(self) -> dict[str, Any]:
        return {
            "original_policy": self.policy,
            "remediated_policy": self.remediated_policy,
            "changes": self.changes,
            "reasoning": self.reasoning,
        }

    def summary_table(self) -> Table:
        table = Table(title="AWS IAM Policy Classification")
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Classification", self.classification.upper())
        table.add_row("Reason", self.reason)
        table.add_row("Findings", str(len(self.findings)))
        if self.changes:
            table.add_row("Changes", str(len(self.changes)))
        return table
