"""Command-line interface for the Enterprise Detection Lab."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, config
from . import lab as lab_controller
from .detection import BaselineResult, DetectionResult, run_baseline, run_detections
from .errors import EDLError, ValidationError
from .ingest import IngestResult
from .ingest import ingest_domain as run_ingest_domain
from .lab import ServiceStatus
from .metrics import (
    load_detection_metrics,
    metrics_report_is_current,
    write_metrics_report,
)
from .report import render_json, render_markdown, render_table
from .telemetry import load_sources, matrix_is_current, write_matrix
from .template import new_detection as create_detection
from .template import new_investigation as create_investigation
from .validation import validate_repository

console = Console()
app = typer.Typer(no_args_is_help=True, add_completion=False)
lab_app = typer.Typer(no_args_is_help=True, help="Local lab lifecycle.")
telemetry_app = typer.Typer(no_args_is_help=True, help="Telemetry source contracts.")
new_app = typer.Typer(no_args_is_help=True, help="Scaffold reference artifacts.")
ingest_app = typer.Typer(no_args_is_help=True, help="Ingest telemetry into the local lab.")
detection_app = typer.Typer(no_args_is_help=True, help="Execute detection packages.")
app.add_typer(lab_app, name="lab")
app.add_typer(telemetry_app, name="telemetry")
app.add_typer(new_app, name="new")
app.add_typer(ingest_app, name="ingest")
app.add_typer(detection_app, name="detection")


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


@new_app.command("detection")
def new_detection(
    domain: str = typer.Option(
        ...,
        "--domain",
        help="identity, endpoint, cloud, saas, network, kubernetes, agent",
    ),
    slug: str = typer.Option(..., "--slug", help="Lowercase hyphen-separated slug."),
    detection_id: str = typer.Option(..., "--id", help="Stable DET-XXX-NNN ID."),
    title: str = typer.Option(..., "--title", help="Detection title."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print the target without writing."),
) -> None:
    """Scaffold a valid detection package from the reference template."""
    try:
        target = create_detection(
            domain=domain,
            slug=slug,
            detection_id=detection_id,
            title=title,
            dry_run=dry_run,
        )
    except EDLError as exc:
        console.print(f"[red]Could not create detection:[/red] {exc}")
        raise typer.Exit(1) from exc

    if dry_run:
        console.print(f"Would create: {target}")
    else:
        console.print(f"[green]Created:[/green] {target}")
        console.print("Run `make validate` after editing the reference behavior.")


@new_app.command("investigation")
def new_investigation(
    slug: str = typer.Option(..., "--slug", help="Lowercase hyphen-separated slug."),
    investigation_id: str = typer.Option(..., "--id", help="Stable INV-NNN ID."),
    title: str = typer.Option(..., "--title", help="Investigation title."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print the target without writing."),
) -> None:
    """Scaffold a valid investigation package from the reference template."""
    try:
        target = create_investigation(
            slug=slug,
            investigation_id=investigation_id,
            title=title,
            dry_run=dry_run,
        )
    except EDLError as exc:
        console.print(f"[red]Could not create investigation:[/red] {exc}")
        raise typer.Exit(1) from exc

    if dry_run:
        console.print(f"Would create: {target}")
    else:
        console.print(f"[green]Created:[/green] {target}")
        console.print("Run `make validate` after editing the reference scenario.")


def _run_ingest_command(
    domain: str,
    source: str | None,
    dry_run: bool,
    json_output: bool,
    refresh: bool,
    batch_size: int,
) -> None:
    requested = tuple(part.strip() for part in source.split(",") if part.strip()) if source else ()
    try:
        results = run_ingest_domain(
            domain,
            config.ROOT,
            sources=requested,
            dry_run=dry_run,
            refresh=refresh,
            batch_size=batch_size,
        )
    except EDLError as exc:
        console.print(f"[red]Ingest failed:[/red] {exc}")
        raise typer.Exit(2) from exc

    if json_output:
        typer.echo(
            json.dumps(
                [result.to_dict() for result in results],
                indent=2,
                sort_keys=True,
            )
        )
    else:
        console.print(render_ingest_table(results, title=f"{domain.title()} Telemetry Ingest"))


@ingest_app.command("identity")
def ingest_identity(
    source: str | None = typer.Option(
        None,
        "--source",
        help="Comma-separated identity source IDs; defaults to all.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Normalize and validate without writing to OpenSearch.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    refresh: bool = typer.Option(
        True,
        "--refresh/--no-refresh",
        help="Refresh indices before counting documents.",
    ),
    batch_size: int = typer.Option(
        500,
        "--batch-size",
        min=1,
        help="Documents per bulk request.",
    ),
) -> None:
    """Ingest Entra sign-in and audit telemetry into OpenSearch."""
    _run_ingest_command("identity", source, dry_run, json_output, refresh, batch_size)


@ingest_app.command("endpoint")
def ingest_endpoint(
    source: str | None = typer.Option(
        None,
        "--source",
        help="Comma-separated endpoint source IDs; defaults to all.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Normalize and validate without writing to OpenSearch.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    refresh: bool = typer.Option(
        True,
        "--refresh/--no-refresh",
        help="Refresh indices before counting documents.",
    ),
    batch_size: int = typer.Option(
        500,
        "--batch-size",
        min=1,
        help="Documents per bulk request.",
    ),
) -> None:
    """Ingest Sysmon and Windows Security telemetry into OpenSearch."""
    _run_ingest_command("endpoint", source, dry_run, json_output, refresh, batch_size)


@ingest_app.command("cloud")
def ingest_cloud(
    source: str | None = typer.Option(
        None,
        "--source",
        help="Comma-separated cloud source IDs; defaults to all.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Normalize and validate without writing to OpenSearch.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    refresh: bool = typer.Option(
        True,
        "--refresh/--no-refresh",
        help="Refresh indices before counting documents.",
    ),
    batch_size: int = typer.Option(
        500,
        "--batch-size",
        min=1,
        help="Documents per bulk request.",
    ),
) -> None:
    """Ingest AWS CloudTrail telemetry into OpenSearch."""
    _run_ingest_command("cloud", source, dry_run, json_output, refresh, batch_size)


def render_ingest_table(results: list[IngestResult], *, title: str) -> Table:
    """Render ingest results as a compact table."""
    table = Table(title=title)
    table.add_column("Source")
    table.add_column("Events", justify="right")
    table.add_column("Unique", justify="right")
    table.add_column("Dups", justify="right")
    table.add_column("Written", justify="right")
    table.add_column("Indices")
    table.add_column("Mode")

    for result in results:
        table.add_row(
            result.source,
            str(result.read),
            str(result.unique),
            str(result.duplicates),
            str(result.written),
            ", ".join(result.indices),
            result.mode,
        )
    return table


@detection_app.command("test")
def detection_test(
    detection_id: str | None = typer.Option(
        None,
        "--id",
        help="Detection ID to run; defaults to all non-template detections.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    include_templates: bool = typer.Option(
        False,
        "--include-templates",
        help="Include reference templates when running all detections.",
    ),
    write_metrics: bool = typer.Option(
        False,
        "--write-metrics",
        help="Write metrics.json for passing detections.",
    ),
    latency_runs: int = typer.Option(
        5,
        "--latency-runs",
        min=1,
        help="Query repetitions used for latency percentiles.",
    ),
) -> None:
    """Run detection queries against their fixtures in OpenSearch."""
    try:
        results = run_detections(
            config.ROOT,
            detection_id=detection_id,
            include_templates=include_templates,
            write_metrics=write_metrics,
            latency_runs=latency_runs,
        )
    except EDLError as exc:
        console.print(f"[red]Detection test failed:[/red] {exc}")
        raise typer.Exit(2) from exc

    if json_output:
        typer.echo(
            json.dumps(
                [result.to_dict() for result in results],
                indent=2,
                sort_keys=True,
            )
        )
    else:
        console.print(render_detection_table(results))

    if not all(result.passed for result in results):
        raise typer.Exit(1)


@detection_app.command("baseline")
def detection_baseline(
    detection_id: str = typer.Option(..., "--id", help="Detection ID to evaluate."),
    dataset: Path = typer.Option(..., "--dataset", help="Benign baseline JSON dataset."),
    query: Path | None = typer.Option(
        None,
        "--query",
        help="Alternative query path relative to the detection package.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    latency_runs: int = typer.Option(
        3,
        "--latency-runs",
        min=1,
        help="Query repetitions used for latency percentiles.",
    ),
) -> None:
    """Evaluate a detection query against a benign baseline dataset."""
    try:
        result = run_baseline(
            detection_id,
            dataset,
            query_path=query,
            latency_runs=latency_runs,
        )
    except EDLError as exc:
        console.print(f"[red]Baseline evaluation failed:[/red] {exc}")
        raise typer.Exit(2) from exc

    if json_output:
        typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        console.print(render_baseline_table(result))


def render_baseline_table(result: BaselineResult) -> Table:
    """Render a baseline evaluation result."""
    table = Table(title="Benign Baseline Evaluation")
    table.add_column("Detection", no_wrap=True)
    table.add_column("Dataset", no_wrap=True)
    table.add_column("Unit", no_wrap=True)
    table.add_column("Cases", justify="right")
    table.add_column("Matched", justify="right")
    table.add_column("FPR", justify="right")
    table.add_column("p95ms", justify="right")
    table.add_row(
        result.detection_id,
        result.dataset.name,
        result.evaluation_unit,
        str(result.sample_size),
        str(result.matched_count),
        f"{result.false_positive_rate:.2f}",
        f"{result.latency_ms_p95:.1f}",
    )
    return table


def render_detection_table(results: list[DetectionResult]) -> Table:
    """Render detection fixture results."""
    table = Table(title="Detection Fixture Replay")
    table.add_column("Detection", no_wrap=True)
    table.add_column("Cases", justify="right")
    table.add_column("TP/FN/FP/TN", justify="right", no_wrap=True)
    table.add_column("Prec", justify="right")
    table.add_column("Rec", justify="right")
    table.add_column("FPR", justify="right")
    table.add_column("p95ms", justify="right", no_wrap=True)
    table.add_column("Status", no_wrap=True)

    for result in results:
        status = "[green]passed[/green]" if result.passed else "[red]failed[/red]"
        table.add_row(
            result.detection_id,
            str(result.sample_size),
            f"{result.true_positives}/{result.false_negatives}/"
            f"{result.false_positives}/{result.true_negatives}",
            f"{result.precision:.2f}",
            f"{result.recall:.2f}",
            f"{result.false_positive_rate:.2f}",
            f"{result.latency_ms_p95:.1f}",
            status,
        )
    return table


@detection_app.command("report")
def detection_report(
    output: Path = typer.Option(
        config.ROOT / "reports" / "detection-metrics.md",
        "--output",
        help="Metrics report output path.",
    ),
    check: bool = typer.Option(
        False,
        "--check",
        help="Fail if the committed metrics report is stale.",
    ),
) -> None:
    """Generate or verify the aggregated detection metrics report."""
    try:
        metrics = load_detection_metrics(config.ROOT)
    except EDLError as exc:
        console.print(f"[red]Could not load detection metrics:[/red] {exc}")
        raise typer.Exit(2) from exc

    target = output if output.is_absolute() else config.ROOT / output
    if check:
        if not metrics_report_is_current(target, metrics):
            console.print(f"[red]Detection metrics report is stale:[/red] {target}")
            console.print("Run `edl detection report` to regenerate it.")
            raise typer.Exit(1)
        console.print(f"[green]Detection metrics report is current:[/green] {target}")
        return

    write_metrics_report(target, metrics)
    console.print(f"[green]Wrote detection metrics report:[/green] {target}")


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
