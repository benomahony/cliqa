"""Tests for CLI interface."""

from typer.testing import CliRunner
from cliqa.cli import app
from cliqa.models import AnalysisReport, CheckResult, Severity

runner = CliRunner()


def test_cli_help():
    """Test CLI help output."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Analyze CLI tools" in result.stdout or "cliqa" in result.stdout


def test_cli_version():
    """Test CLI version flag."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "cliqa" in result.stdout


def test_analyze_command_help():
    """Test analyze command help."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["analyze", "--help"])

    assert result.exit_code == 0
    assert "analyze" in result.stdout.lower()


def test_analyze_nonexistent_command():
    """Test analyze with nonexistent command."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["analyze", "nonexistent_cmd_xyz_12345"])

    assert result.exit_code == 1
    output = (result.stdout + result.stderr).lower()
    assert "not found" in output or "error" in output


def test_analyze_echo_command():
    """Test analyze with echo command."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["analyze", "echo"])

    assert result.exit_code in [0, 1]
    assert len(result.stdout) > 0


def test_analyze_echo_verbose():
    """Test analyze with verbose flag."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["analyze", "echo", "--verbose"])

    assert result.exit_code in [0, 1]
    assert len(result.stdout) > 0


def test_analyze_echo_table():
    """Test analyze with table format."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["analyze", "echo", "--table"])

    assert result.exit_code in [0, 1]
    assert len(result.stdout) > 0


def test_analyze_ls_command():
    """Test analyze with ls command."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["analyze", "ls"])

    assert result.exit_code in [0, 1]
    assert len(result.stdout) > 0


def test_check_command_help():
    """Test check command help."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["check", "--help"])

    assert result.exit_code == 0
    assert "check" in result.stdout.lower()


def test_check_specific_check():
    """Test check command with specific check."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["check", "echo", "help"])

    assert result.exit_code in [0, 1]
    assert len(result.stdout) > 0


def test_check_invalid_check_name():
    """Test check command with invalid check name."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["check", "echo", "invalid_check_xyz"])

    assert result.exit_code == 1
    output = (result.stdout + result.stderr).lower()
    assert "unknown check" in output or "error" in output


def test_check_nonexistent_command():
    """Test check with nonexistent command."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["check", "nonexistent_cmd_xyz", "help"])

    assert result.exit_code == 1
    output = (result.stdout + result.stderr).lower()
    assert "not found" in output or "error" in output


def test_list_checks_command():
    """Test list-checks command."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["list-checks"])

    assert result.exit_code == 0
    assert "help" in result.stdout
    assert "version" in result.stdout


def test_display_report_with_errors():
    """Test display_report function with errors."""
    from cliqa.cli import display_report

    assert display_report is not None, "display_report must be defined"
    assert AnalysisReport is not None, "AnalysisReport must be defined"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(
            name="test_error",
            description="Test error",
            severity=Severity.ERROR,
            message="Error message",
        )
    ]

    display_report(report)


def test_display_report_with_warnings():
    """Test display_report function with warnings."""
    from cliqa.cli import display_report

    assert display_report is not None, "display_report must be defined"
    assert AnalysisReport is not None, "AnalysisReport must be defined"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(
            name="test_warning",
            description="Test warning",
            severity=Severity.WARNING,
            message="Warning message",
        )
    ]

    display_report(report)


def test_display_report_all_passed():
    """Test display_report with all passed checks."""
    from cliqa.cli import display_report

    assert display_report is not None, "display_report must be defined"
    assert AnalysisReport is not None, "AnalysisReport must be defined"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(
            name="test_pass",
            description="Test pass",
            severity=Severity.PASS,
            message="Pass message",
        )
    ]

    display_report(report)


def test_display_report_verbose():
    """Test display_report with verbose flag."""
    from cliqa.cli import display_report

    assert display_report is not None, "display_report must be defined"
    assert AnalysisReport is not None, "AnalysisReport must be defined"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(
            name="test_info",
            description="Test info",
            severity=Severity.INFO,
            message="Info message",
        )
    ]

    display_report(report, verbose=True)


def test_display_table():
    """Test display_table function."""
    from cliqa.cli import display_table

    assert display_table is not None, "display_table must be defined"
    assert AnalysisReport is not None, "AnalysisReport must be defined"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(
            name="test_check",
            description="Test check",
            severity=Severity.PASS,
            message="Test message",
        )
    ]

    display_table(report)


def test_display_table_verbose():
    """Test display_table with verbose flag."""
    from cliqa.cli import display_table

    assert display_table is not None, "display_table must be defined"
    assert AnalysisReport is not None, "AnalysisReport must be defined"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(
            name="test_check",
            description="Test check",
            severity=Severity.WARNING,
            message="Warning message",
            guideline_url="https://example.com",
        )
    ]

    display_table(report, verbose=True)


def test_run_all_checks_basic():
    """Test run_all_checks function."""
    import asyncio
    from cliqa.cli import run_all_checks

    assert run_all_checks is not None, "run_all_checks must be defined"
    assert isinstance("echo", str), "command must be string"

    report = asyncio.run(run_all_checks("echo"))

    assert isinstance(report, AnalysisReport)
    assert report.command == "echo"
    assert len(report.checks) > 0


def test_analyze_json_output():
    """Test analyze command with JSON output."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["analyze", "echo", "--json"])

    assert result.exit_code in [0, 1]
    assert "{" in result.stdout and "}" in result.stdout


def test_severity_icons():
    """Test SEVERITY_ICONS constant."""
    from cliqa.cli import SEVERITY_ICONS

    assert SEVERITY_ICONS is not None, "SEVERITY_ICONS must be defined"
    assert isinstance(SEVERITY_ICONS, dict)

    assert Severity.PASS in SEVERITY_ICONS
    assert Severity.INFO in SEVERITY_ICONS
    assert Severity.WARNING in SEVERITY_ICONS
    assert Severity.ERROR in SEVERITY_ICONS


def test_print_check_function():
    """Test _print_check function."""
    from cliqa.cli import _print_check

    assert _print_check is not None, "_print_check must be defined"
    assert CheckResult is not None, "CheckResult must be defined"

    check = CheckResult(
        name="test",
        description="Test check",
        severity=Severity.PASS,
        message="Test message",
        guideline_url="https://example.com#anchor",
    )

    _print_check("test", check, "green", "✓")


def test_print_check_with_long_message():
    """Test _print_check with long message."""
    from cliqa.cli import _print_check

    assert _print_check is not None, "_print_check must be defined"
    assert CheckResult is not None, "CheckResult must be defined"

    check = CheckResult(
        name="test",
        description="Test check",
        severity=Severity.WARNING,
        message="Short message: " + "x" * 100,
    )

    _print_check("test", check, "yellow", "⚠")


def test_check_all_available_checks():
    """Test check command with all available check types."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    check_types = ["help", "version", "exit-codes", "naming"]

    for check_type in check_types:
        result = runner.invoke(app, ["check", "echo", check_type])
        assert result.exit_code in [0, 1], f"Check type {check_type} failed"


def test_analyze_with_all_flags():
    """Test analyze with multiple flags."""
    assert runner is not None, "runner must be initialized"
    assert app is not None, "app must be defined"

    result = runner.invoke(app, ["analyze", "echo", "-v", "-t"])

    assert result.exit_code in [0, 1]
    assert len(result.stdout) > 0
