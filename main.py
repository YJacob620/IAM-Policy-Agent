from __future__ import annotations

import typer
from rich.console import Console

from agent.orchestrator import Orchestrator
from utils.file_io import PolicyInputError, load_policy, save_output
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
        False, "--verbose", "-v", help="Stream agent reasoning and tool calls."
    ),
) -> None:
    """Classify an AWS IAM policy and remediate it when it is weak."""

    try:
        policy_data = load_policy(policy)
    except PolicyInputError as exc:
        console.print(f"[bold red]Input validation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    try:
        result = Orchestrator(verbose=verbose).run(policy_data)
    except GeminiError as exc:
        console.print(f"[bold red]Gemini request failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    saved_paths = save_output(result, output_dir, source_path=policy)

    console.print(result.summary_table())
    console.print(
        f"[bold green][Saved][/bold green] Classification result -> {saved_paths['classification_path']}"
    )
    if saved_paths["remediated_path"]:
        console.print(
            f"[bold green][Saved][/bold green] Remediated policy -> {saved_paths['remediated_path']}"
        )


if __name__ == "__main__":
    app()
