"""CLI entry point for the IAM policy classifier and remediator."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console

from agent.agent import RemediatingAgent
from agent.orchestrator import Orchestrator
from models.output import OutputModel
from utils.file_io import (
    PolicyInputError,
    load_policy,
    save_classification_output,
    save_remediation_output,
)
from utils.gemini import GeminiError


app = typer.Typer(add_completion=False)
console = Console()


@app.command()
def analyze(
    policy: str = typer.Option(
        ..., "--policy", "-p", help="Path to an IAM policy JSON file."
    ),
    output_dir: str = typer.Option(
        "output", "--output-dir", "-o", help="Directory for output JSON files."
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Stream deterministic analysis plus classification/remediation details.",
    ),
) -> None:
    """Run the end-to-end policy workflow from file input to saved artifacts.

    The command performs preflight validation before any Gemini call is made,
    then executes deterministic analysis plus Gemini classification/remediation
    and writes the classification artifact
    for every valid policy plus a remediated artifact for weak policies.
    """

    try:
        policy_data = load_policy(policy)
    except PolicyInputError as exc:
        console.print(f"[bold red]Input validation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    orchestrator = Orchestrator(verbose=verbose)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        classification_result = orchestrator.classify(policy_data)
    except GeminiError as exc:
        console.print(f"[bold red]Gemini request failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    classification_path = save_classification_output(
        classification_result,
        output_dir,
        source_path=policy,
        timestamp=timestamp,
    )
    console.print(
        f"[bold green][Saved][/bold green] Classification result -> {classification_path}"
    )

    result = classification_result
    if classification_result.classification == "Weak":
        try:
            result = orchestrator.remediate(classification_result)
        except GeminiError as exc:
            console.print(f"[bold red]Gemini remediation failed:[/bold red] {exc}")
            console.print(classification_result.summary_table())
            raise typer.Exit(code=1) from exc

        remediated_path = save_remediation_output(
            result,
            output_dir,
            source_path=policy,
            timestamp=timestamp,
        )
        console.print(
            f"[bold green][Saved][/bold green] Remediated policy -> {remediated_path}"
        )

    console.print(result.summary_table())


@app.command("remediate-from-prompt")
def remediate_from_prompt(
    policy: str = typer.Option(
        ..., "--policy", "-p", help="Path to the original IAM policy JSON file."
    ),
    prompt_file: str = typer.Option(
        ...,
        "--prompt-file",
        help="Path to a UTF-8 txt file containing the full remediation prompt contents.",
    ),
    output_dir: str = typer.Option(
        "output", "--output-dir", "-o", help="Directory for output JSON files."
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Print recovery-mode progress and output details.",
    ),
) -> None:
    """Run remediation-only recovery mode from a prepared prompt text file.

    This command skips deterministic analysis and classification, and executes
    only the remediation Gemini call using the exact prompt contents read from
    disk.
    """

    try:
        policy_data = load_policy(policy)
    except PolicyInputError as exc:
        console.print(f"[bold red]Input validation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    prompt_path = Path(prompt_file)
    try:
        prompt_contents = prompt_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        console.print(f"[bold red]Prompt file was not found:[/bold red] {prompt_path}")
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        console.print(
            f"[bold red]Unable to read prompt file:[/bold red] {prompt_path} ({exc})"
        )
        raise typer.Exit(code=1) from exc

    if not prompt_contents.strip():
        console.print("[bold red]Prompt file is empty.[/bold red]")
        raise typer.Exit(code=1)

    if verbose:
        console.print(
            "[yellow][Recovery Mode][/yellow] Running remediation-only flow from prompt file."
        )

    try:
        remediation_result = RemediatingAgent().remediate_from_contents(prompt_contents)
    except (GeminiError, ValueError) as exc:
        console.print(f"[bold red]Gemini remediation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    result = OutputModel.model_validate(
        {
            "policy": policy_data,
            "classification": "Weak",
            "reason": "Remediation-only recovery mode (classification step skipped).",
            "findings": [],
            **remediation_result,
        }
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    remediated_path = save_remediation_output(
        result,
        output_dir,
        source_path=policy,
        timestamp=timestamp,
    )
    if remediated_path is None:
        console.print("[bold red]Failed to persist remediation artifact.[/bold red]")
        raise typer.Exit(code=1)

    console.print(
        f"[bold green][Saved][/bold green] Remediated policy -> {remediated_path}"
    )
    console.print(result.summary_table())


if __name__ == "__main__":
    app()
