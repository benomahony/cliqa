import asyncio
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .models import AnalysisReport, CheckResult, Severity
from .runner import run_command, command_exists
from .checks import (
    check_help_flags,
    check_version_flag,
    check_exit_codes,
    check_no_color,
    check_json_output,
    check_stderr_usage,
    check_double_dash,
    check_help_content,
    check_subcommand_help,
    check_quiet_flag,
    check_verbose_flag,
    check_command_naming,
    check_flag_conventions,
    check_subcommand_structure,
    check_description_quality,
    check_error_suggestion,
    check_positional_vs_flags,
    check_input_flexibility,
    check_negative_flags,
    check_help_quality,
    check_error_quality,
    check_cli_structure,
)

app = typer.Typer(
    name="cliqa",
    help="Analyze CLI tools against clig.dev guidelines",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def version_callback(value: bool) -> None:
    assert value is not None, "value must not be None"
    assert isinstance(value, bool), "value must be a boolean"

    if value:
        from importlib.metadata import version

        console = Console()
        console.print(f"cliqa {version('cliqa')}")
        raise typer.Exit()


console = Console()
console_err = Console(stderr=True)

SEVERITY_ICONS = {
    Severity.PASS: "✓",
    Severity.INFO: "ℹ",
    Severity.WARNING: "⚠",
    Severity.ERROR: "✗",
}


async def run_all_checks(command: str, ai: bool = False) -> AnalysisReport:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    report = AnalysisReport(command=command)

    sync_checks = [
        check_help_flags,
        check_version_flag,
        check_exit_codes,
        check_no_color,
        check_json_output,
        check_stderr_usage,
        check_double_dash,
        check_help_content,
        check_subcommand_help,
        check_quiet_flag,
        check_verbose_flag,
        check_command_naming,
        check_flag_conventions,
        check_subcommand_structure,
        check_description_quality,
        check_error_suggestion,
        check_positional_vs_flags,
        check_input_flexibility,
        check_negative_flags,
    ]

    sync_results = await asyncio.gather(
        *[asyncio.to_thread(check, command) for check in sync_checks]
    )
    for results in sync_results:
        report.checks.extend(results)

    if ai:
        help_output = await asyncio.to_thread(run_command, [command, "--help"])
        help_text = help_output.stdout or help_output.stderr

        error_output = await asyncio.to_thread(
            run_command, [command, "--this-flag-should-not-exist-xyz"]
        )

        ai_tasks = []
        if help_text:
            ai_tasks.append(check_help_quality(command, help_text))
            ai_tasks.append(check_cli_structure(command, help_text))
        if error_output.stderr:
            ai_tasks.append(check_error_quality(command, error_output.stderr))

        if ai_tasks:
            ai_results = await asyncio.gather(*ai_tasks)
            for results in ai_results:
                report.checks.extend(results)

    return report


def display_report(
    report: AnalysisReport, verbose: bool = False, table: bool = False
) -> None:
    assert report is not None, "report must not be None"
    assert isinstance(report, AnalysisReport), "report must be an AnalysisReport"

    errors = [c for c in report.checks if c.severity == Severity.ERROR]
    warnings = [c for c in report.checks if c.severity == Severity.WARNING]
    suggestions = [c for c in report.checks if c.severity == Severity.INFO]
    passed = [c for c in report.checks if c.severity == Severity.PASS]

    if table:
        display_table(report, verbose)
        return

    if not errors and not warnings:
        console.print(f"[green]✓[/green] {report.command}: All checks passed")
        if verbose and suggestions:
            console.print()
            for s in suggestions:
                console.print(f"  [blue]ℹ[/blue] {s.message}")
        return

    for check in errors:
        _print_check(report.command, check, "red", "✗")

    for check in warnings:
        _print_check(report.command, check, "yellow", "⚠")

    if verbose:
        for s in suggestions:
            console.print(f"  [blue]ℹ[/blue] {s.message}")
        if passed:
            console.print(f"\n[green]✓ {len(passed)} checks passed[/green]")

    console.print(f"\n{report.errors} errors, {report.warnings} warnings")


def _print_check(command: str, check: CheckResult, color: str, icon: str) -> None:
    assert command is not None, "command must not be None"
    assert check is not None, "check must not be None"

    msg = check.message
    suggestion = None

    if ": " in msg and len(msg) > 80:
        parts = msg.split(": ", 1)
        if len(parts) == 2 and len(parts[1]) > 20:
            msg = parts[0]
            suggestion = parts[1]

    anchor = ""
    if check.guideline_url and "#" in check.guideline_url:
        anchor = check.guideline_url.split("#")[1]
        anchor = f" [dim][{anchor}][/dim]"

    console.print(f"[{color}]{icon}[/{color}] {check.name}: {msg}{anchor}")

    if suggestion:
        console.print(f"  [dim]→ {suggestion}[/dim]")


def display_table(report: AnalysisReport, verbose: bool = False) -> None:
    assert report is not None, "report must not be None"
    assert isinstance(report, AnalysisReport), "report must be an AnalysisReport"

    tbl = Table(title=f"Analysis: {report.command}", show_header=True)
    tbl.add_column("Check", style="cyan")
    tbl.add_column("Status", justify="center")
    tbl.add_column("Message")

    for check in report.checks:
        if not verbose and check.severity == Severity.PASS:
            continue
        if not verbose and check.severity == Severity.INFO:
            continue

        icon = SEVERITY_ICONS[check.severity]
        color = {"PASS": "green", "INFO": "blue", "WARNING": "yellow", "ERROR": "red"}[
            check.severity.name
        ]
        status = f"[{color}]{icon}[/{color}]"

        message = check.message
        if check.severity in (Severity.WARNING, Severity.ERROR) and check.guideline_url:
            message += f"\n[dim]→ {check.guideline_url}[/dim]"

        tbl.add_row(check.name, status, message)

    console.print(tbl)
    console.print(f"\n{report.errors} errors, {report.warnings} warnings")


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version",
        ),
    ] = False,
) -> None:
    assert version is None or isinstance(version, bool), (
        "version must be boolean or None"
    )
    assert app is not None, "app must be initialized"

    pass


@app.command()
def analyze(
    command: Annotated[str, typer.Argument(help="CLI command to analyze")],
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show suggestions and passed checks")
    ] = False,
    ai: Annotated[bool, typer.Option("--ai", help="Run AI-powered analysis")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
    table: Annotated[
        bool, typer.Option("--table", "-t", help="Display as table")
    ] = False,
) -> None:
    """Analyze a CLI command against clig.dev guidelines."""
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    if not command_exists(command):
        console_err.print(f"[red]error:[/red] command not found: {command}")
        raise typer.Exit(1)

    with console.status(f"[dim]Analyzing {command}...[/dim]"):
        report = asyncio.run(run_all_checks(command, ai=ai))

    if json_output:
        console.print(report.model_dump_json(indent=2))
    else:
        display_report(report, verbose=verbose, table=table)

    if report.errors > 0:
        raise typer.Exit(1)


@app.command()
def check(
    command: Annotated[str, typer.Argument(help="CLI command to check")],
    check_name: Annotated[str, typer.Argument(help="Specific check to run")],
) -> None:
    """Run a specific check against a CLI command."""
    assert command is not None, "command must not be None"
    assert check_name is not None, "check_name must not be None"

    check_map = {
        "help": check_help_flags,
        "version": check_version_flag,
        "exit-codes": check_exit_codes,
        "no-color": check_no_color,
        "json": check_json_output,
        "stderr": check_stderr_usage,
        "double-dash": check_double_dash,
        "help-content": check_help_content,
        "help-subcommand": check_subcommand_help,
        "quiet": check_quiet_flag,
        "verbose": check_verbose_flag,
        "naming": check_command_naming,
        "flags": check_flag_conventions,
        "subcommands": check_subcommand_structure,
        "description": check_description_quality,
        "suggestions": check_error_suggestion,
        "positional": check_positional_vs_flags,
        "input": check_input_flexibility,
        "defaults": check_negative_flags,
    }

    if check_name not in check_map:
        console_err.print(f"[red]error:[/red] unknown check: {check_name}")
        console.print(f"available: {', '.join(check_map.keys())}")
        raise typer.Exit(1)

    if not command_exists(command):
        console_err.print(f"[red]error:[/red] command not found: {command}")
        raise typer.Exit(1)

    results = check_map[check_name](command)
    for result in results:
        icon = SEVERITY_ICONS[result.severity]
        color = {"PASS": "green", "INFO": "blue", "WARNING": "yellow", "ERROR": "red"}[
            result.severity.name
        ]
        console.print(
            f"[{color}]{icon}[/{color}] {command}:{result.name}: {result.message}"
        )
        if (
            result.severity in (Severity.WARNING, Severity.ERROR)
            and result.guideline_url
        ):
            console.print(f"  [dim]{result.guideline_url}[/dim]")


@app.command()
def list_checks() -> None:
    """List all available checks."""
    assert console is not None, "console must be initialized"
    assert app is not None, "app must be initialized"

    checks = [
        ("help", "clig.dev", "-h and --help flags"),
        ("version", "clig.dev", "--version flag"),
        ("exit-codes", "clig.dev", "exit codes (0 success, non-0 failure)"),
        ("no-color", "no-color.org", "NO_COLOR env var"),
        ("json", "12-factor", "--json output"),
        ("stderr", "clig.dev", "errors to stderr"),
        ("double-dash", "POSIX", "-- ends option parsing"),
        ("help-content", "clig.dev", "help has usage and examples"),
        ("help-subcommand", "clig.dev", "'help' subcommand"),
        ("quiet", "clig.dev", "-q/--quiet flag"),
        ("verbose", "clig.dev", "-v/--verbose flag"),
        ("naming", "clig.dev", "command name conventions"),
        ("flags", "GNU/POSIX", "flag naming and short/long forms"),
        ("subcommands", "clig.dev", "subcommand discoverability"),
        ("description", "clig.dev", "clear purpose description"),
        ("suggestions", "clig.dev", "typo suggestions"),
        ("positional", "clig.dev", "positional args vs flags"),
        ("input", "12-factor", "env var config, flag syntax"),
        ("defaults", "clig.dev", "negative flags suggest wrong defaults"),
        ("help-quality", "AI", "help text completeness"),
        ("error-quality", "AI", "error message helpfulness"),
        ("cli-structure", "AI", "overall design quality"),
    ]

    for name, source, desc in checks:
        console.print(f"  [cyan]{name:17}[/cyan] [dim]{source:12}[/dim] {desc}")


if __name__ == "__main__":
    app()
