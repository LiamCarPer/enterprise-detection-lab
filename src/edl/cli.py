"""Command-line interface for the Enterprise Detection Lab."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, config
from . import lab as lab_controller
from .errors import EDLError, ValidationError
from .lab import ServiceStatus
from .report import render_json, render_markdown, render_table
from .telemetry import load_sources, matrix_is_current, write_matrix
from .validation import validate_repository

console = Console()
app = typer.Typer(no_args_is_help=True, add_completion=False)
lab_app = typer.Typer(no_args_is_help=True, help="Local lab lifecycle.")
telemetry_app = typer.Typer(no_args_is_help=True, help="Telemetry source contracts.")
app.add_typer(lab_app, name="lab")
app.add_typer(telemetry_app, name="telemetry")


@app.command()
def version() -> None:
    """Print the CLI version."""
    console.print(f"edl {__version__}")


@app.command()
def validate(
    path: Path | None = typer.Option(
        None,
        "--path",
        help="Only validate artifacts under this path.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as errors."),
    sigma: bool = typer.Option(False, "--sigma", help="Run sigma check on rules."),
) -> None:
    """Validate detection, investigation, and telemetry artifacts."""
    try:
        report = validate_repository(
            config.ROOT,
            include_path=path,
            check_sigma=sigma,
            strict=strict,
        )
    except (EDLError, OSError) as exc:
        console.print(f"[red]Validation failed to run:[/red] {exc}")
        raise typer.Exit(2) from exc

    if json_output:
        typer.echo(render_json(report))
    else:
        console.print(render_table(report))

    if not report.ok:
        raise typer.Exit(1)


@app.command()
def report(
    output_format: str = typer.Option(
        "table",
        "--format",
        case_sensitive=False,
        help="table, json, or markdown",
    ),
) -> None:
    """Validate the repository and render a report."""
    selected = output_format.lower()
    if selected not in {"table", "json", "markdown"}:
        console.print("[red]--format must be table, json, or markdown[/red]")
        raise typer.Exit(2)

    try:
        validation_report = validate_repository(config.ROOT)
    except (EDLError, OSError) as exc:
        console.print(f"[red]Validation failed to run:[/red] {exc}")
        raise typer.Exit(2) from exc

    if selected == "json":
        typer.echo(render_json(validation_report))
    elif selected == "markdown":
        typer.echo(render_markdown(validation_report), nl=False)
    else:
        console.print(render_table(validation_report))

    if not validation_report.ok:
        raise typer.Exit(1)


@telemetry_app.command("matrix")
def telemetry_matrix(
    check: bool = typer.Option(False, "--check", help="Fail if the committed matrix is stale."),
    output: Path = typer.Option(
        config.ROOT / "docs" / "telemetry-matrix.md",
        "--output",
        help="Matrix output path.",
    ),
) -> None:
    """Generate or verify the telemetry source matrix."""
    try:
        sources = load_sources(config.ROOT)
    except ValidationError as exc:
        console.print(f"[red]Could not load telemetry sources:[/red] {exc}")
        raise typer.Exit(2) from exc

    target = output if output.is_absolute() else config.ROOT / output
    if check:
        if not matrix_is_current(target, sources):
            console.print(f"[red]Telemetry matrix is stale:[/red] {target}")
            console.print("Run `edl telemetry matrix` to regenerate it.")
            raise typer.Exit(1)
        console.print(f"[green]Telemetry matrix is current:[/green] {target}")
        return

    write_matrix(target, sources)
    console.print(f"[green]Wrote telemetry matrix:[/green] {target}")


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
    statuses = lab_controller.status()
    console.print(render_lab_table(statuses))
    if not all(item.healthy for item in statuses):
        raise typer.Exit(1)


def render_lab_table(statuses: list[ServiceStatus]) -> Table:
    """Render the lab health table."""
    table = Table(title="Enterprise Detection Lab")
    table.add_column("Service")
    table.add_column("URL")
    table.add_column("State")
    table.add_column("Detail")

    for item in statuses:
        state = "[green]healthy[/green]" if item.healthy else "[red]unhealthy[/red]"
        table.add_row(item.name, item.url, state, item.detail)
    return table


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
