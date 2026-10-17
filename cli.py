"""
Soteria — CLI Entrypoint

Command-line interface for running red-team audits, viewing reports,
and launching the interactive dashboard.

Usage:
    python cli.py run                        # Run full audit
    python cli.py run --filter LLM01         # Run only LLM01 objectives
    python cli.py run --max-turns 3          # Override max iterations
    python cli.py report                     # Generate HTML report from latest audit
    python cli.py dashboard                  # Launch Streamlit dashboard
    python cli.py list-objectives            # Show all available objectives
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from core.config_loader import load_objectives, load_target_config
from core.database import DatabaseLogger
from core.orchestrator import run_audit
from reports.html_report import generate_html_report

console = Console()


def _setup_logging(verbose: bool) -> None:
    """Configure structured logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(
            console=console,
            rich_tracebacks=True,
            show_path=False,
        )],
    )
    # Quiet noisy libraries.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("litellm").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.pass_context
def cli(ctx, verbose):
    """⚔️  Soteria — Automated Adversarial Red-Teaming Harness"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


# ╭──────────────────────────────────────────────────────────────╮
# │  RUN Command                                                │
# ╰──────────────────────────────────────────────────────────────╯

@cli.command()
@click.option(
    "--config", "-c", "config_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to target_config.yaml (default: config/target_config.yaml).",
)
@click.option(
    "--objectives", "-o", "objectives_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to objectives.yaml (default: config/objectives.yaml).",
)
@click.option(
    "--filter", "-f", "obj_filter",
    multiple=True,
    help="Only run objectives matching these ID prefixes (e.g., --filter LLM01).",
)
@click.option(
    "--max-turns", "-t",
    type=int,
    default=None,
    help="Override max iterations per objective.",
)
@click.option(
    "--concurrency", "-j",
    type=int,
    default=None,
    help="Override max concurrent objectives.",
)
@click.option(
    "--no-remediate",
    is_flag=True,
    help="Disable auto-remediation on breach.",
)
@click.option(
    "--report/--no-report",
    default=True,
    help="Generate HTML report after audit (default: yes).",
)
@click.pass_context
def run(ctx, config_path, objectives_path, obj_filter, max_turns,
        concurrency, no_remediate, report):
    """Run a red-team audit against the configured target."""

    # Load configuration.
    config = load_target_config(config_path)
    objectives = load_objectives(objectives_path)

    # Apply CLI overrides.
    if max_turns is not None:
        config.max_turns = max_turns
    if concurrency is not None:
        config.concurrency = concurrency
    if no_remediate:
        config.auto_remediate = False

    # Convert filter tuple to list (or None).
    filter_list = list(obj_filter) if obj_filter else None

    # Run the async audit loop.
    audit_report = asyncio.run(
        run_audit(config, objectives, objective_filter=filter_list)
    )

    # Generate HTML report if requested.
    if report and audit_report.runs:
        output_dir = Path("reports_output")
        filepath = generate_html_report(audit_report, output_dir)
        console.print(f"\n📄 HTML report saved to: [link=file://{filepath}]{filepath}[/]")

    # Exit code for CI/CD integration.
    if not audit_report.ci_gate_passed:
        console.print(
            "\n[bold red]❌ CI/CD gate FAILED — "
            f"ASR {audit_report.asr_percent:.1f}% exceeds threshold.[/]"
        )
        sys.exit(1)

    console.print("\n[bold green]✅ Audit complete. CI/CD gate passed.[/]")


# ╭──────────────────────────────────────────────────────────────╮
# │  REPORT Command                                             │
# ╰──────────────────────────────────────────────────────────────╯

@cli.command()
@click.option(
    "--db", "db_path",
    default="soteria_results.db",
    help="Path to the SQLite database.",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=Path("reports_output"),
    help="Output directory for the HTML report.",
)
@click.option(
    "--audit-id",
    default=None,
    help="Specific audit ID to report (default: latest).",
)
def report(db_path, output, audit_id):
    """Generate an HTML report from a previous audit run."""

    async def _generate():
        async with DatabaseLogger(db_path) as db:
            audits = await db.get_all_audits()
            if not audits:
                console.print("[yellow]No audits found in database.[/]")
                return

            target_audit = audits[0]  # Latest by default.
            if audit_id:
                target_audit = next(
                    (a for a in audits if a['audit_id'] == audit_id), None,
                )
                if not target_audit:
                    console.print(f"[red]Audit ID '{audit_id}' not found.[/]")
                    return

            # Reconstruct a minimal AuditReport for the HTML generator.
            from core.models import AuditReport
            r = AuditReport(
                audit_id=target_audit['audit_id'],
                total_objectives=target_audit['total_objectives'],
                breached_objectives=target_audit['breached_objectives'],
                asr_percent=target_audit['asr_percent'],
                total_tokens=target_audit['total_tokens'],
                total_cost_usd=target_audit['total_cost_usd'],
                ci_gate_passed=bool(target_audit['ci_gate_passed']),
            )
            filepath = generate_html_report(r, output)
            console.print(f"📄 Report saved to: {filepath}")

    asyncio.run(_generate())


# ╭──────────────────────────────────────────────────────────────╮
# │  DASHBOARD Command                                          │
# ╰──────────────────────────────────────────────────────────────╯

@cli.command()
@click.option(
    "--port", "-p",
    type=int,
    default=8501,
    help="Port for the Streamlit server.",
)
def dashboard(port):
    """Launch the interactive Streamlit dashboard."""
    dashboard_path = Path(__file__).parent / "reports" / "dashboard.py"

    if not dashboard_path.exists():
        console.print("[red]Dashboard file not found.[/]")
        return

    console.print(f"🚀 Launching dashboard on port {port}...")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run",
         str(dashboard_path), "--server.port", str(port)],
        check=True,
    )


# ╭──────────────────────────────────────────────────────────────╮
# │  LIST-OBJECTIVES Command                                    │
# ╰──────────────────────────────────────────────────────────────╯

@cli.command("list-objectives")
@click.option(
    "--objectives", "-o", "objectives_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to objectives.yaml.",
)
def list_objectives(objectives_path):
    """Display all available attack objectives."""
    objectives = load_objectives(objectives_path)

    table = Table(
        title="🎯 Available Attack Objectives",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("ID", style="cyan", max_width=25)
    table.add_column("Title", max_width=35)
    table.add_column("OWASP Category", max_width=30)
    table.add_column("Severity")
    table.add_column("Canaries", justify="center")

    for obj in objectives:
        sev_style = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "green", "info": "blue",
        }.get(obj.severity.value, "white")
        table.add_row(
            obj.id,
            obj.title,
            obj.owasp_category,
            f"[{sev_style}]{obj.severity.value.upper()}[/]",
            str(len(obj.canary_tokens)),
        )

    console.print(table)


# ╭──────────────────────────────────────────────────────────────╮
# │  Main                                                        │
# ╰──────────────────────────────────────────────────────────────╯

def main():
    cli(obj={})


if __name__ == "__main__":
    main()
