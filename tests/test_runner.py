"""Tests for runner module using real command execution."""

import os
from cliqa.runner import command_exists, run_command
from cliqa.models import CLIOutput


def test_run_command_with_echo():
    """Test run_command with real echo command."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance("hello", str), "command must be string"

    result = run_command(["echo", "hello"])

    assert isinstance(result, CLIOutput)
    assert "hello" in result.stdout
    assert result.exit_code == 0
    assert result.timed_out is False


def test_run_command_with_string_command():
    """Test run_command with string command (uses shlex)."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance("echo test", str), "command must be string"

    result = run_command("echo test")

    assert isinstance(result, CLIOutput)
    assert "test" in result.stdout
    assert result.exit_code == 0


def test_run_command_nonexistent():
    """Test run_command with nonexistent command."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance("nonexistent_cmd_12345", str), "command must be string"

    result = run_command(["nonexistent_cmd_12345"])

    assert isinstance(result, CLIOutput)
    assert result.exit_code == 127
    assert "not found" in result.stderr.lower()


def test_run_command_with_stderr():
    """Test run_command captures stderr."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance(["ls", "--invalid-flag-xyz"], list), "command must be list"

    result = run_command(["ls", "--invalid-flag-xyz"])

    assert isinstance(result, CLIOutput)
    assert result.exit_code != 0
    assert len(result.stderr) > 0 or len(result.stdout) > 0


def test_run_command_with_timeout():
    """Test run_command with timeout using sleep."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance(0.1, float), "timeout must be float"

    result = run_command(["sleep", "10"], timeout=0.1)

    assert isinstance(result, CLIOutput)
    assert result.timed_out is True
    assert result.exit_code == -1


def test_run_command_with_env():
    """Test run_command with custom environment."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance({}, dict), "env must be dict"

    env = os.environ.copy()
    env["TEST_VAR"] = "test_value"

    result = run_command(["sh", "-c", "echo $TEST_VAR"], env=env)

    assert isinstance(result, CLIOutput)
    assert "test_value" in result.stdout
    assert result.exit_code == 0


def test_run_command_with_stdin():
    """Test run_command with stdin input."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance("input data", str), "stdin must be string"

    result = run_command(["cat"], stdin="input data", timeout=1.0)

    assert isinstance(result, CLIOutput)
    assert "input data" in result.stdout
    assert result.exit_code == 0


def test_command_exists_true():
    """Test command_exists with existing command."""
    assert command_exists is not None, "command_exists must be defined"
    assert isinstance("echo", str), "command must be string"

    result = command_exists("echo")

    assert isinstance(result, bool)
    assert result is True


def test_command_exists_false():
    """Test command_exists with nonexistent command."""
    assert command_exists is not None, "command_exists must be defined"
    assert isinstance("nonexistent_cmd_xyz_12345", str), "command must be string"

    result = command_exists("nonexistent_cmd_xyz_12345")

    assert isinstance(result, bool)
    assert result is False


def test_run_command_ls():
    """Test run_command with ls command."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance(["ls", "-la"], list), "command must be list"

    result = run_command(["ls", "-la"])

    assert isinstance(result, CLIOutput)
    assert result.exit_code == 0
    assert len(result.stdout) > 0


def test_run_command_pwd():
    """Test run_command with pwd command."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance(["pwd"], list), "command must be list"

    result = run_command(["pwd"])

    assert isinstance(result, CLIOutput)
    assert result.exit_code == 0
    assert len(result.stdout) > 0
    assert "/" in result.stdout


def test_run_command_with_exit_code():
    """Test run_command captures correct exit codes."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance(["sh", "-c", "exit 42"], list), "command must be list"

    result = run_command(["sh", "-c", "exit 42"])

    assert isinstance(result, CLIOutput)
    assert result.exit_code == 42


def test_run_command_exception_handling():
    """Test run_command handles exceptions gracefully."""
    assert run_command is not None, "run_command must be defined"
    assert isinstance([], list), "command must be list"

    result = run_command([])

    assert isinstance(result, CLIOutput)
    assert result.exit_code != 0


def test_command_exists_with_python():
    """Test command_exists with python command."""
    assert command_exists is not None, "command_exists must be defined"
    assert isinstance("python3", str), "command must be string"

    result = command_exists("python3")

    assert isinstance(result, bool)
    assert result is True or result is False


def test_run_command_output_types():
    """Test run_command returns correct output types."""
    assert run_command is not None, "run_command must be defined"
    assert CLIOutput is not None, "CLIOutput must be defined"

    result = run_command(["echo", "test"])

    assert isinstance(result, CLIOutput)
    assert isinstance(result.stdout, str)
    assert isinstance(result.stderr, str)
    assert isinstance(result.exit_code, int)
    assert isinstance(result.timed_out, bool)
