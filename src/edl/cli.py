"""Command-line interface for the Enterprise Detection Lab."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, config
from . import lab as lab_controller
from .errors import EDLError

console = Console()
app = typer.Typer(no_args_is_help=True, add_completion=False)
lab_app = typer.Typer(no_args_is_help=True, help="Local lab lifecycle.")
app.add_typer(lab_app, name="lab")


@app.command()
def version() -> None:
    """Print the CLI version."""
    console.print(f"edl {__version__}")


@app.command()
def validate() -> None:
    """Validate repository contracts that exist in this phase.

    This is intentionally narrow in Commit 2. Commit 3 replaces it with full
    artifact, telemetry, fixture, and metrics validation.
    """
    errors: list[str] = []

    schemas = sorted(config.SCHEMAS_DIR.glob("*.json"))
    if not schemas:
        errors.append(f"No schemas found in {config.SCHEMAS_DIR}")
    for schema in schemas:
        try:
            json.loads(schema.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{schema.relative_to(config.ROOT)}: invalid JSON: {exc}")

    required = [
        config.ROOT / "README.md",
        config.ROOT / "docs" / "artifact-model.md",
        config.ROOT / "detections" / "README.md",
        config.ROOT / "investigations" / "README.md",
    ]
    for path in required:
        if not path.exists():
            errors.append(f"Missing required file: {path.relative_to(config.ROOT)}")

    if errors:
        for error in errors:
            console.print(f"[red]ERROR[/red] {error}")
        raise typer.Exit(1)

    console.print(
        f"[green]Repository checks passed[/green] "
        f"({len(schemas)} schema(s), {len(required)} required file(s))"
    )


@lab_app.command("up")
def lab_up() -> None:
    """Start the local lab and wait for health."""
    try:
        lab_controller.up()
    except (EDLError, RuntimeError) as exc:
        console.print(f"[red]Lab start failed:[/red] {exc}")
        raise typer.Exit(2) from exc
    console.print("[green]Lab is healthy.[/green]")


@lab_app.command("down")
def lab_down() -> None:
    """Stop the local lab without deleting data."""
    lab_controller.down()
    console.print("Lab stopped.")


@lab_app.command("status")
def lab_status() -> None:
    """Show the health of every lab component."""
    table = Table(title="Enterprise Detection Lab")
    table.add_column("Service")
    table.add_column("URL")
    table.add_column("State")
    table.add_column("Detail")

    statuses = lab_controller.status()
    for item in statuses:
        state = "[green]healthy[/green]" if item.healthy else "[red]unhealthy[/red]"
        table.add_row(item.name, item.url, state, item.detail)

    console.print(table)
    if not all(item.healthy for item in statuses):
        raise typer.Exit(1)


@lab_app.command("wait")
def lab_wait(timeout: int = typer.Option(180, help="Seconds to wait.")) -> None:
    """Wait for the lab to become healthy."""
    try:
        lab_controller.wait(timeout=timeout)
    except EDLError as exc:
        console.print(f"[red]Lab not ready:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print("[green]Lab is healthy.[/green]")


@lab_app.command("bootstrap")
def lab_bootstrap() -> None:
    """Apply OpenSearch templates, Kusto schema, and DuckDB schema."""
    try:
        lab_controller.bootstrap()
    except EDLError as exc:
        console.print(f"[red]Bootstrap failed:[/red] {exc}")
        raise typer.Exit(2) from exc
    console.print("[green]Lab bootstrap complete.[/green]")


@lab_app.command("reset")
def lab_reset(yes: bool = typer.Option(False, "--yes", help="Confirm data deletion.")) -> None:
    """Stop the lab and delete its named volumes."""
    if not yes:
        console.print("[red]Refusing to delete lab data without --yes.[/red]")
        raise typer.Exit(1)
    lab_controller.reset()
    console.print("Lab reset. Volumes deleted.")


@lab_app.command("logs")
def lab_logs(
    service: str | None = typer.Argument(None, help="Optional service name."),
    follow: bool = typer.Option(True, "--follow/--no-follow", help="Follow logs."),
) -> None:
    """Stream compose logs."""
    lab_controller.logs(service=service, follow=follow)


if __name__ == "__main__":  # pragma: no cover
    app()
