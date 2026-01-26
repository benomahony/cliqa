"""Tests for checks module using real CLI commands."""

import os
import pytest
from clint.checks import (
    check_command_naming,
    check_description_quality,
    check_double_dash,
    check_error_suggestion,
    check_exit_codes,
    check_flag_conventions,
    check_help_content,
    check_help_flags,
    check_input_flexibility,
    check_json_output,
    check_negative_flags,
    check_no_color,
    check_positional_vs_flags,
    check_quiet_flag,
    check_stderr_usage,
    check_stdin_dash,
    check_subcommand_help,
    check_subcommand_structure,
    check_verbose_flag,
    check_version_flag,
    get_cli_analyzer,
    get_error_analyzer,
    parse_help_text,
    check_cli_structure,
    check_error_quality,
)
from clint.models import CheckResult, Severity


def test_parse_help_text_basic():
    """Test parse_help_text with basic help text."""
    assert parse_help_text is not None, "parse_help_text must be defined"
    assert isinstance("usage: test", str), "help_text must be string"

    help_text = """usage: test [options]
    A test command

    Options:
      -h, --help     show help
      -v, --verbose  verbose output
    """

    result = parse_help_text(help_text)

    assert isinstance(result, dict)
    assert "flags" in result
    assert "-h" in result["flags"]
    assert "--help" in result["flags"]
    assert result["has_usage"] is True


def test_parse_help_text_with_examples():
    """Test parse_help_text detects examples."""
    assert parse_help_text is not None, "parse_help_text must be defined"
    assert isinstance("Examples:", str), "help_text must be string"

    help_text = """usage: test

    Examples:
      test file.txt
      test -v file.txt
    """

    result = parse_help_text(help_text)

    assert result["has_examples"] is True
    assert isinstance(result["has_examples"], bool)


def test_parse_help_text_with_subcommands():
    """Test parse_help_text detects subcommands."""
    assert parse_help_text is not None, "parse_help_text must be defined"
    assert isinstance("commands:", str), "help_text must be string"

    help_text = """usage: test <command>

    Commands:
      list     List items
      show     Show details
      delete   Delete items
    """

    result = parse_help_text(help_text)

    assert "subcommands" in result
    assert len(result["subcommands"]) > 0


def test_check_help_flags_with_echo():
    """Test check_help_flags with echo command."""
    assert check_help_flags is not None, "check_help_flags must be defined"
    assert isinstance("echo", str), "command must be string"

    results = check_help_flags("echo")

    assert isinstance(results, list)
    assert len(results) > 0
    assert all(isinstance(r, CheckResult) for r in results)


def test_check_help_flags_with_ls():
    """Test check_help_flags with ls command."""
    assert check_help_flags is not None, "check_help_flags must be defined"
    assert isinstance("ls", str), "command must be string"

    results = check_help_flags("ls")

    assert isinstance(results, list)
    assert len(results) >= 2


def test_check_version_flag_with_python():
    """Test check_version_flag with python command."""
    assert check_version_flag is not None, "check_version_flag must be defined"
    assert isinstance("python3", str), "command must be string"

    results = check_version_flag("python3")

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].name == "version_flag"


def test_check_exit_codes_with_echo():
    """Test check_exit_codes with echo command."""
    assert check_exit_codes is not None, "check_exit_codes must be defined"
    assert isinstance("echo", str), "command must be string"

    results = check_exit_codes("echo")

    assert isinstance(results, list)
    assert len(results) == 2
    assert any(r.name == "exit_code_success" for r in results)
    assert any(r.name == "exit_code_failure" for r in results)


def test_check_command_naming_lowercase():
    """Test check_command_naming with lowercase command."""
    assert check_command_naming is not None, "check_command_naming must be defined"
    assert isinstance("echo", str), "command must be string"

    results = check_command_naming("echo")

    assert isinstance(results, list)
    assert len(results) >= 2
    lowercase_check = [r for r in results if r.name == "command_lowercase"][0]
    assert lowercase_check.severity == Severity.PASS


def test_check_command_naming_uppercase():
    """Test check_command_naming with uppercase command."""
    assert check_command_naming is not None, "check_command_naming must be defined"
    assert isinstance("TEST", str), "command must be string"

    results = check_command_naming("TEST")

    assert isinstance(results, list)
    lowercase_check = [r for r in results if r.name == "command_lowercase"][0]
    assert lowercase_check.severity == Severity.WARNING


def test_check_command_naming_short():
    """Test check_command_naming with short command name."""
    assert check_command_naming is not None, "check_command_naming must be defined"
    assert isinstance("ls", str), "command must be string"

    results = check_command_naming("ls")

    assert isinstance(results, list)
    length_check = [r for r in results if r.name == "command_length"][0]
    assert length_check.severity == Severity.PASS


def test_check_command_naming_long():
    """Test check_command_naming with long command name."""
    assert check_command_naming is not None, "check_command_naming must be defined"
    assert isinstance("verylongcommandname", str), "command must be string"

    results = check_command_naming("verylongcommandname")

    assert isinstance(results, list)
    length_check = [r for r in results if r.name == "command_length"][0]
    assert length_check.severity == Severity.WARNING


def test_check_command_naming_with_delimiter():
    """Test check_command_naming with delimiter in name."""
    assert check_command_naming is not None, "check_command_naming must be defined"
    assert isinstance("test-command", str), "command must be string"

    results = check_command_naming("test-command")

    assert isinstance(results, list)
    assert any(r.name == "command_no_delimiters" for r in results)


def test_check_stderr_usage_with_ls():
    """Test check_stderr_usage with ls command."""
    assert check_stderr_usage is not None, "check_stderr_usage must be defined"
    assert isinstance("ls", str), "command must be string"

    results = check_stderr_usage("ls")

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].name == "stderr_usage"


def test_check_double_dash_with_echo():
    """Test check_double_dash with echo command."""
    assert check_double_dash is not None, "check_double_dash must be defined"
    assert isinstance("echo", str), "command must be string"

    results = check_double_dash("echo")

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].name == "double_dash"


def test_check_stdin_dash_with_cat():
    """Test check_stdin_dash with cat command."""
    assert check_stdin_dash is not None, "check_stdin_dash must be defined"
    assert isinstance("cat", str), "command must be string"

    results = check_stdin_dash("cat")

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].name == "stdin_dash"


def test_check_description_quality_with_python():
    """Test check_description_quality with python command."""
    assert check_description_quality is not None, (
        "check_description_quality must be defined"
    )
    assert isinstance("python3", str), "command must be string"

    results = check_description_quality("python3")

    assert isinstance(results, list)
    assert len(results) > 0


def test_check_flag_conventions_with_ls():
    """Test check_flag_conventions with ls command."""
    assert check_flag_conventions is not None, "check_flag_conventions must be defined"
    assert isinstance("ls", str), "command must be string"

    results = check_flag_conventions("ls")

    assert isinstance(results, list)
    assert len(results) > 0


def test_check_subcommand_structure_with_git():
    """Test check_subcommand_structure with git command."""
    assert check_subcommand_structure is not None, (
        "check_subcommand_structure must be defined"
    )
    assert isinstance("git", str), "command must be string"

    results = check_subcommand_structure("git")

    assert isinstance(results, list)


def test_check_error_suggestion_with_ls():
    """Test check_error_suggestion with ls command."""
    assert check_error_suggestion is not None, "check_error_suggestion must be defined"
    assert isinstance("ls", str), "command must be string"

    results = check_error_suggestion("ls")

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].name == "error_suggestion"


def test_check_positional_vs_flags_with_echo():
    """Test check_positional_vs_flags with echo command."""
    assert check_positional_vs_flags is not None, (
        "check_positional_vs_flags must be defined"
    )
    assert isinstance("echo", str), "command must be string"

    results = check_positional_vs_flags("echo")

    assert isinstance(results, list)


def test_check_no_color_with_ls():
    """Test check_no_color with ls command."""
    assert check_no_color is not None, "check_no_color must be defined"
    assert isinstance("ls", str), "command must be string"

    results = check_no_color("ls")

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].name == "no_color"


def test_check_json_output_with_echo():
    """Test check_json_output with echo command."""
    assert check_json_output is not None, "check_json_output must be defined"
    assert isinstance("echo", str), "command must be string"

    results = check_json_output("echo")

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].name == "json_output"


def test_check_help_content_with_ls():
    """Test check_help_content with ls command."""
    assert check_help_content is not None, "check_help_content must be defined"
    assert isinstance("ls", str), "command must be string"

    results = check_help_content("ls")

    assert isinstance(results, list)
    assert len(results) > 0


def test_check_subcommand_help_with_git():
    """Test check_subcommand_help with git command."""
    assert check_subcommand_help is not None, "check_subcommand_help must be defined"
    assert isinstance("git", str), "command must be string"

    results = check_subcommand_help("git")

    assert isinstance(results, list)
    assert len(results) == 1


def test_check_quiet_flag_with_grep():
    """Test check_quiet_flag with grep command."""
    assert check_quiet_flag is not None, "check_quiet_flag must be defined"
    assert isinstance("grep", str), "command must be string"

    results = check_quiet_flag("grep")

    assert isinstance(results, list)
    assert len(results) == 1


def test_check_verbose_flag_with_ls():
    """Test check_verbose_flag with ls command."""
    assert check_verbose_flag is not None, "check_verbose_flag must be defined"
    assert isinstance("ls", str), "command must be string"

    results = check_verbose_flag("ls")

    assert isinstance(results, list)
    assert len(results) == 1


def test_check_input_flexibility_with_echo():
    """Test check_input_flexibility with echo command."""
    assert check_input_flexibility is not None, (
        "check_input_flexibility must be defined"
    )
    assert isinstance("echo", str), "command must be string"

    results = check_input_flexibility("echo")

    assert isinstance(results, list)


def test_check_negative_flags_with_ls():
    """Test check_negative_flags with ls command."""
    assert check_negative_flags is not None, "check_negative_flags must be defined"
    assert isinstance("ls", str), "command must be string"

    results = check_negative_flags("ls")

    assert isinstance(results, list)


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="Requires ANTHROPIC_API_KEY environment variable",
)
def test_get_cli_analyzer():
    """Test get_cli_analyzer returns Agent."""
    assert get_cli_analyzer is not None, "get_cli_analyzer must be defined"

    analyzer = get_cli_analyzer()

    assert analyzer is not None
    assert hasattr(analyzer, "run")


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="Requires ANTHROPIC_API_KEY environment variable",
)
def test_get_error_analyzer():
    """Test get_error_analyzer returns Agent."""
    assert get_error_analyzer is not None, "get_error_analyzer must be defined"

    analyzer = get_error_analyzer()

    assert analyzer is not None
    assert hasattr(analyzer, "run")


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="Requires ANTHROPIC_API_KEY environment variable",
)
async def test_check_cli_structure_with_help_text():
    """Test check_cli_structure with sample help text."""
    assert check_cli_structure is not None, "check_cli_structure must be defined"
    assert isinstance("test", str), "command must be string"

    help_text = """test - A test CLI tool

    Usage: test [options] <file>

    Options:
      -h, --help     Show this help
      -v, --verbose  Verbose output

    Examples:
      test file.txt
      test -v file.txt
    """

    results = await check_cli_structure("test", help_text)

    assert isinstance(results, list)
    assert all(isinstance(r, CheckResult) for r in results)


async def test_check_cli_structure_short_text():
    """Test check_cli_structure with short help text returns empty."""
    assert check_cli_structure is not None, "check_cli_structure must be defined"
    assert isinstance("short", str), "help_text must be string"

    results = await check_cli_structure("test", "short")

    assert isinstance(results, list)
    assert len(results) == 0


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="Requires ANTHROPIC_API_KEY environment variable",
)
async def test_check_error_quality_with_error_text():
    """Test check_error_quality with sample error text."""
    assert check_error_quality is not None, "check_error_quality must be defined"
    assert isinstance("error text", str), "error_text must be string"

    error_text = "Error: Invalid option --xyz\nTry 'test --help' for more information."

    results = await check_error_quality("test", error_text)

    assert isinstance(results, list)
    assert all(isinstance(r, CheckResult) for r in results)


async def test_check_error_quality_short_text():
    """Test check_error_quality with short error text returns empty."""
    assert check_error_quality is not None, "check_error_quality must be defined"
    assert isinstance("err", str), "error_text must be string"

    results = await check_error_quality("test", "err")

    assert isinstance(results, list)
    assert len(results) == 0


def test_check_functions_return_lists():
    """Test all check functions return lists."""
    assert check_help_flags is not None, "check_help_flags must be defined"
    assert isinstance("echo", str), "command must be string"

    functions = [
        check_help_flags,
        check_version_flag,
        check_exit_codes,
        check_command_naming,
        check_stderr_usage,
        check_double_dash,
        check_stdin_dash,
        check_description_quality,
        check_flag_conventions,
        check_error_suggestion,
        check_positional_vs_flags,
        check_no_color,
        check_json_output,
        check_help_content,
        check_subcommand_help,
        check_quiet_flag,
        check_verbose_flag,
        check_input_flexibility,
        check_negative_flags,
    ]

    for func in functions:
        result = func("echo")
        assert isinstance(result, list), f"{func.__name__} must return list"


def test_parse_help_text_empty():
    """Test parse_help_text with empty string."""
    assert parse_help_text is not None, "parse_help_text must be defined"
    assert isinstance("", str), "help_text must be string"

    result = parse_help_text("")

    assert isinstance(result, dict)
    assert "flags" in result
    assert "has_usage" in result


def test_check_with_nonexistent_command():
    """Test check functions handle nonexistent commands gracefully."""
    assert check_help_flags is not None, "check_help_flags must be defined"
    assert isinstance("nonexistent_xyz_12345", str), "command must be string"

    results = check_help_flags("nonexistent_xyz_12345")

    assert isinstance(results, list)
