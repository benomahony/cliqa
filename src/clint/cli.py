import asyncio
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .models import AnalysisReport, Severity
from .runner import run_command, command_exists
from .checks import (
    check_help_flags,
    check_version_flag,
    check_exit_codes,
    check_no_color,
    check_json_output,
    check_stderr_usage,
    check_double_dash,
    check_stdin_dash,
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
    check_help_quality,
    check_error_quality,
    check_cli_structure,
)

app = typer.Typer(
    name="clint",
    help="Analyze CLI tools against clig.dev guidelines",
    no_args_is_help=True,
)
console = Console()
console_err = Console(stderr=True)

SEVERITY_COLORS = {
    Severity.PASS: "green",
    Severity.INFO: "blue",
    Severity.WARNING: "yellow",
    Severity.ERROR: "red",
}

SEVERITY_ICONS = {
    Severity.PASS: "✓",
    Severity.INFO: "ℹ",
    Severity.WARNING: "⚠",
    Severity.ERROR: "✗",
}


async def run_all_checks(command: str, skip_ai: bool = False) -> AnalysisReport:
    report = AnalysisReport(command=command)
    
    report.checks.extend(check_help_flags(command))
    report.checks.extend(check_version_flag(command))
    report.checks.extend(check_exit_codes(command))
    report.checks.extend(check_no_color(command))
    report.checks.extend(check_json_output(command))
    report.checks.extend(check_stderr_usage(command))
    report.checks.extend(check_double_dash(command))
    report.checks.extend(check_help_content(command))
    report.checks.extend(check_subcommand_help(command))
    report.checks.extend(check_quiet_flag(command))
    report.checks.extend(check_verbose_flag(command))
    report.checks.extend(check_command_naming(command))
    report.checks.extend(check_flag_conventions(command))
    report.checks.extend(check_subcommand_structure(command))
    report.checks.extend(check_description_quality(command))
    report.checks.extend(check_error_suggestion(command))
    report.checks.extend(check_positional_vs_flags(command))
    report.checks.extend(check_input_flexibility(command))
    
    if not skip_ai:
        help_output = run_command([command, "--help"])
        help_text = help_output.stdout or help_output.stderr
        if help_text:
            report.checks.extend(await check_help_quality(command, help_text))
            report.checks.extend(await check_cli_structure(command, help_text))
        
        error_output = run_command([command, "--this-flag-should-not-exist-xyz"])
        if error_output.stderr:
            report.checks.extend(await check_error_quality(command, error_output.stderr))
    
    return report


def display_report(report: AnalysisReport, verbose: bool = False) -> None:
    table = Table(title=f"Analysis: {report.command}", show_header=True)
    table.add_column("Check", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Message")
    
    for check in report.checks:
        icon = SEVERITY_ICONS[check.severity]
        color = SEVERITY_COLORS[check.severity]
        status = f"[{color}]{icon}[/{color}]"
        
        message = check.message
        if verbose and check.details:
            message += f"\n[dim]{check.details}[/dim]"
        
        if check.severity in (Severity.WARNING, Severity.ERROR) and check.guideline_url:
            message += f"\n[dim]→ {check.guideline_url}[/dim]"
        
        table.add_row(check.name, status, message)
    
    console.print(table)
    
    summary_parts = [
        f"[green]{report.passed} passed[/green]",
        f"[yellow]{report.warnings} warnings[/yellow]",
        f"[red]{report.errors} errors[/red]",
    ]
    console.print(f"\nSummary: {', '.join(summary_parts)}")
    
    if report.errors > 0:
        console.print("\n[dim]See https://clig.dev for full guidelines[/dim]")


@app.command()
def analyze(
    command: Annotated[str, typer.Argument(help="CLI command to analyze")],
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show detailed output")] = False,
    skip_ai: Annotated[bool, typer.Option("--skip-ai", help="Skip AI-powered analysis")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
) -> None:
    """Analyze a CLI command against clig.dev guidelines."""
    if not command_exists(command):
        console_err.print(f"[red]Command not found: {command}[/red]")
        raise typer.Exit(1)
    
    with console.status(f"[bold blue]Analyzing {command}...[/bold blue]"):
        report = asyncio.run(run_all_checks(command, skip_ai=skip_ai))
    
    if json_output:
        console.print(report.model_dump_json(indent=2))
    else:
        display_report(report, verbose=verbose)
    
    if report.errors > 0:
        raise typer.Exit(1)


@app.command()
def check(
    command: Annotated[str, typer.Argument(help="CLI command to check")],
    check_name: Annotated[str, typer.Argument(help="Specific check to run")],
) -> None:
    """Run a specific check against a CLI command."""
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
    }
    
    if check_name not in check_map:
        console_err.print(f"[red]Unknown check: {check_name}[/red]")
        console.print(f"Available: {', '.join(check_map.keys())}")
        raise typer.Exit(1)
    
    if not command_exists(command):
        console_err.print(f"[red]Command not found: {command}[/red]")
        raise typer.Exit(1)
    
    results = check_map[check_name](command)
    for result in results:
        icon = SEVERITY_ICONS[result.severity]
        color = SEVERITY_COLORS[result.severity]
        console.print(f"[{color}]{icon} {result.name}[/{color}]: {result.message}")
        if result.severity in (Severity.WARNING, Severity.ERROR) and result.guideline_url:
            console.print(f"  [dim]→ {result.guideline_url}[/dim]")


@app.command()
def list_checks() -> None:
    """List all available checks."""
    checks = [
        ("help", "Verify -h and --help flags work"),
        ("version", "Verify --version flag works"),
        ("exit-codes", "Check exit codes (0 success, non-0 failure)"),
        ("no-color", "Check NO_COLOR env var is respected"),
        ("json", "Check for JSON output support (--json)"),
        ("stderr", "Verify errors go to stderr"),
        ("double-dash", "Check -- ends option parsing (POSIX)"),
        ("help-content", "Check help includes usage and examples"),
        ("help-subcommand", "Check for 'help' subcommand (git-style)"),
        ("quiet", "Check for -q/--quiet flag"),
        ("verbose", "Check for -v/--verbose or -d/--debug flag"),
        ("naming", "Check command name (lowercase, short, no delimiters)"),
        ("flags", "Check flag naming conventions and short/long forms"),
        ("subcommands", "Analyze subcommand discoverability and help"),
        ("description", "Check if CLI has clear purpose description"),
        ("suggestions", "Check if typos trigger helpful suggestions"),
        ("positional", "Check positional args vs flags balance"),
        ("input", "Check input flexibility (env vars, flag syntax)"),
        ("help-quality", "AI: Boolean checks for help completeness + suggestions"),
        ("error-quality", "AI: Boolean checks for error helpfulness + suggestions"),
        ("cli-structure", "AI: 10 boolean checks for design quality + suggestions"),
    ]
    
    table = Table(title="Available Checks")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("Source", style="dim")
    
    sources = {
        "help": "clig.dev",
        "version": "clig.dev",
        "exit-codes": "clig.dev",
        "no-color": "no-color.org",
        "json": "12-factor CLI",
        "stderr": "clig.dev",
        "double-dash": "POSIX",
        "help-content": "clig.dev",
        "help-subcommand": "clig.dev",
        "quiet": "clig.dev",
        "verbose": "clig.dev",
        "naming": "clig.dev",
        "flags": "GNU/POSIX",
        "subcommands": "clig.dev",
        "description": "clig.dev",
        "suggestions": "clig.dev",
        "positional": "clig.dev",
        "input": "12-factor CLI",
        "help-quality": "AI",
        "error-quality": "AI",
        "cli-structure": "AI",
    }
    
    for name, desc in checks:
        table.add_row(name, desc, sources.get(name, ""))
    
    console.print(table)


if __name__ == "__main__":
    app()
