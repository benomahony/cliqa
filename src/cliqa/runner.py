import subprocess
import shlex
from .models import CLIOutput


def run_command(
    command: str | list[str],
    timeout: float = 5.0,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> CLIOutput:
    assert command is not None, "command must not be None"
    assert timeout > 0, "timeout must be positive"

    if isinstance(command, str):
        args = shlex.split(command)
    else:
        args = command

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            input=stdin,
        )
        return CLIOutput(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return CLIOutput(
            stdout="",
            stderr="Command timed out",
            exit_code=-1,
            timed_out=True,
        )
    except FileNotFoundError:
        return CLIOutput(
            stdout="",
            stderr=f"Command not found: {args[0]}",
            exit_code=127,
        )
    except Exception as e:
        return CLIOutput(
            stdout="",
            stderr=str(e),
            exit_code=-1,
        )


def command_exists(command: str) -> bool:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    result = run_command(["which", command])
    return result.exit_code == 0
