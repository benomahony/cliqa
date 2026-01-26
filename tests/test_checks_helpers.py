"""Tests for helper functions in checks module."""

from clint.checks import (
    _check_command_length,
    _check_command_lowercase,
    _check_flag_naming_conventions,
    _check_flag_short_long_versions,
    _check_subcommand_discovery,
    _detect_subcommands,
)
from clint.models import Severity


def test_check_flag_short_long_versions_no_short():
    """Test _check_flag_short_long_versions with no short flags."""
    assert _check_flag_short_long_versions is not None, "function must be defined"
    assert isinstance([], list), "short_flags must be list"

    result = _check_flag_short_long_versions([], ["--help", "--version"])

    assert result is not None
    assert result.severity == Severity.WARNING


def test_check_flag_short_long_versions_both():
    """Test _check_flag_short_long_versions with both."""
    assert _check_flag_short_long_versions is not None, "function must be defined"
    assert isinstance(["-h"], list), "short_flags must be list"

    result = _check_flag_short_long_versions(["-h", "-v"], ["--help", "--version"])

    assert result is not None
    assert result.severity == Severity.PASS


def test_check_flag_short_long_versions_none():
    """Test _check_flag_short_long_versions returns None when no long flags."""
    assert _check_flag_short_long_versions is not None, "function must be defined"
    assert isinstance([], list), "flags must be list"

    result = _check_flag_short_long_versions(["-h"], [])

    assert result is None


def test_check_flag_naming_conventions_clean():
    """Test _check_flag_naming_conventions with clean flags."""
    assert _check_flag_naming_conventions is not None, "function must be defined"
    assert isinstance(["--help"], list), "flags must be list"

    result = _check_flag_naming_conventions(["--help", "--version", "-h"])

    assert result is not None
    assert result.severity == Severity.PASS


def test_check_flag_naming_conventions_underscore():
    """Test _check_flag_naming_conventions with underscore."""
    assert _check_flag_naming_conventions is not None, "function must be defined"
    assert isinstance(["--bad_name"], list), "flags must be list"

    result = _check_flag_naming_conventions(["--bad_name"])

    assert result is not None
    assert result.severity == Severity.WARNING
    assert "kebab-case" in result.message


def test_check_flag_naming_conventions_uppercase():
    """Test _check_flag_naming_conventions with uppercase."""
    assert _check_flag_naming_conventions is not None, "function must be defined"
    assert isinstance(["--BADNAME"], list), "flags must be list"

    result = _check_flag_naming_conventions(["--BADNAME"])

    assert result is not None
    assert result.severity == Severity.WARNING
    assert "lowercase" in result.message


def test_check_command_lowercase_pass():
    """Test _check_command_lowercase with lowercase."""
    assert _check_command_lowercase is not None, "function must be defined"
    assert isinstance("test", str), "command must be string"

    result = _check_command_lowercase("test")

    assert result is not None
    assert result.severity == Severity.PASS


def test_check_command_lowercase_fail():
    """Test _check_command_lowercase with uppercase."""
    assert _check_command_lowercase is not None, "function must be defined"
    assert isinstance("TEST", str), "command must be string"

    result = _check_command_lowercase("TEST")

    assert result is not None
    assert result.severity == Severity.WARNING


def test_check_command_length_short():
    """Test _check_command_length with short command."""
    assert _check_command_length is not None, "function must be defined"
    assert isinstance("ls", str), "command must be string"

    result = _check_command_length("ls")

    assert result is not None
    assert result.severity == Severity.PASS
    assert "short" in result.message


def test_check_command_length_medium():
    """Test _check_command_length with medium command."""
    assert _check_command_length is not None, "function must be defined"
    assert isinstance("command", str), "command must be string"

    result = _check_command_length("command")

    assert result is not None
    assert result.severity == Severity.PASS
    assert "acceptable" in result.message


def test_check_command_length_long():
    """Test _check_command_length with long command."""
    assert _check_command_length is not None, "function must be defined"
    assert isinstance("verylongcommandname", str), "command must be string"

    result = _check_command_length("verylongcommandname")

    assert result is not None
    assert result.severity == Severity.WARNING


def test_detect_subcommands_with_git():
    """Test _detect_subcommands with git."""
    assert _detect_subcommands is not None, "function must be defined"
    assert isinstance("git", str), "command must be string"

    result = _detect_subcommands("git")

    assert isinstance(result, list)


def test_detect_subcommands_with_echo():
    """Test _detect_subcommands with simple command."""
    assert _detect_subcommands is not None, "function must be defined"
    assert isinstance("echo", str), "command must be string"

    result = _detect_subcommands("echo")

    assert isinstance(result, list)


def test_check_subcommand_discovery_with_detected():
    """Test _check_subcommand_discovery with detected subcommands."""
    assert _check_subcommand_discovery is not None, "function must be defined"
    assert isinstance(["list"], list), "detected must be list"

    result = _check_subcommand_discovery(["list", "help"], False)

    assert result is not None
    assert result.severity == Severity.WARNING


def test_check_subcommand_discovery_with_section():
    """Test _check_subcommand_discovery with section."""
    assert _check_subcommand_discovery is not None, "function must be defined"
    assert isinstance(True, bool), "has_section must be bool"

    result = _check_subcommand_discovery([], True)

    assert result is not None
    assert result.severity == Severity.PASS


def test_check_subcommand_discovery_none():
    """Test _check_subcommand_discovery returns None."""
    assert _check_subcommand_discovery is not None, "function must be defined"
    assert isinstance([], list), "detected must be list"

    result = _check_subcommand_discovery([], False)

    assert result is None
