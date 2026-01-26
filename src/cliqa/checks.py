import os
import re
from pydantic import BaseModel, Field
from pydantic_ai import Agent

from .models import CheckResult, Severity
from .runner import run_command


GUIDELINES_URL = "https://clig.dev"

STANDARD_FLAGS = {
    "-h": "help",
    "--help": "help",
    "-v": "verbose (or version)",
    "--verbose": "verbose",
    "--version": "version",
    "-V": "version",
    "-q": "quiet",
    "--quiet": "quiet",
    "-f": "force (or file)",
    "--force": "force",
    "-o": "output",
    "--output": "output",
    "-i": "input (or interactive)",
    "--input": "input",
    "-n": "dry-run (or number)",
    "--dry-run": "dry run",
    "-d": "debug",
    "--debug": "debug",
    "-c": "config",
    "--config": "config",
    "-a": "all",
    "--all": "all",
    "-r": "recursive",
    "--recursive": "recursive",
    "-y": "yes/assume yes",
    "--yes": "assume yes",
    "--no-color": "disable color",
    "--json": "JSON output",
    "--format": "output format",
}


def parse_help_text(help_text: str) -> dict:
    """Extract structured info from help text."""
    assert help_text is not None, "help_text must not be None"
    assert isinstance(help_text, str), "help_text must be a string"

    result = {
        "flags": [],
        "subcommands": [],
        "positional_args": [],
        "has_usage": False,
        "has_examples": False,
        "has_description": False,
    }

    flag_pattern = r"(-[a-zA-Z]|--[a-zA-Z][-a-zA-Z0-9]*)"
    result["flags"] = list(set(re.findall(flag_pattern, help_text)))

    subcommand_patterns = [
        r"(?:commands?|subcommands?):\s*\n((?:\s+\w+.*\n)+)",
        r"(?:available commands?):\s*\n((?:\s+\w+.*\n)+)",
    ]
    for pattern in subcommand_patterns:
        match = re.search(pattern, help_text, re.IGNORECASE)
        if match:
            cmd_block = match.group(1)
            cmds = re.findall(r"^\s+(\w+)", cmd_block, re.MULTILINE)
            result["subcommands"] = cmds
            break

    result["has_usage"] = bool(
        re.search(r"(usage|synopsis):", help_text, re.IGNORECASE)
    )
    result["has_examples"] = bool(
        re.search(r"(examples?|e\.g\.):", help_text, re.IGNORECASE)
    )
    result["has_description"] = len(help_text.split("\n")[0].strip()) > 10

    return result


def _check_flag_short_long_versions(
    short_flags: list[str], long_flags: list[str]
) -> CheckResult | None:
    assert short_flags is not None, "short_flags must not be None"
    assert long_flags is not None, "long_flags must not be None"

    if long_flags and not short_flags:
        return CheckResult(
            name="flag_short_versions",
            description="Common flags have short versions",
            severity=Severity.WARNING,
            message="No short flags detected - consider adding -h, -v, etc.",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        )
    elif short_flags and long_flags:
        return CheckResult(
            name="flag_short_versions",
            description="Common flags have short versions",
            severity=Severity.PASS,
            message=f"Has both short ({len(short_flags)}) and long ({len(long_flags)}) flags",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        )
    return None


def _check_flag_naming_conventions(flags: list[str]) -> CheckResult:
    assert flags is not None, "flags must not be None"
    assert isinstance(flags, list), "flags must be a list"

    nonstandard = []
    for flag in flags:
        if flag in STANDARD_FLAGS:
            continue
        if flag.startswith("--"):
            name = flag[2:]
            if "_" in name:
                nonstandard.append(
                    f"{flag} (use kebab-case: --{name.replace('_', '-')})"
                )
            elif name.isupper():
                nonstandard.append(f"{flag} (use lowercase)")

    if nonstandard:
        return CheckResult(
            name="flag_naming",
            description="Flags follow naming conventions",
            severity=Severity.WARNING,
            message=f"Non-standard flag names: {', '.join(nonstandard[:3])}",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        )
    return CheckResult(
        name="flag_naming",
        description="Flags follow naming conventions",
        severity=Severity.PASS,
        message="Flag names follow conventions (lowercase, kebab-case)",
        guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
    )


def check_flag_conventions(command: str) -> list[CheckResult]:
    """Check if flags follow standard naming conventions."""
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    if not help_text:
        return []

    results = []
    parsed = parse_help_text(help_text)
    flags = parsed["flags"]

    short_flags = [f for f in flags if f.startswith("-") and not f.startswith("--")]
    long_flags = [f for f in flags if f.startswith("--")]

    short_long_result = _check_flag_short_long_versions(short_flags, long_flags)
    if short_long_result:
        results.append(short_long_result)

    results.append(_check_flag_naming_conventions(flags))
    return results


def _detect_subcommands(command: str) -> list[str]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    test_cmds = ["list", "help", "version", "status", "info", "get", "create", "delete"]
    detected = []
    for cmd in test_cmds:
        output = run_command([command, cmd, "--help"], timeout=2.0)
        if output.exit_code == 0 and len(output.stdout or output.stderr) > 20:
            detected.append(cmd)
    return detected


def _check_subcommand_discovery(
    detected: list[str], has_section: bool
) -> CheckResult | None:
    assert detected is not None, "detected must not be None"
    assert isinstance(has_section, bool), "has_section must be a boolean"

    if detected and not has_section:
        return CheckResult(
            name="subcommand_discovery",
            description="Subcommands are discoverable in help",
            severity=Severity.WARNING,
            message=f"Has subcommands ({', '.join(detected)}) but help doesn't list them clearly",
            guideline_url=f"{GUIDELINES_URL}/#subcommands",
        )
    elif has_section:
        return CheckResult(
            name="subcommand_discovery",
            description="Subcommands are discoverable in help",
            severity=Severity.PASS,
            message="Help text lists available commands/subcommands",
            guideline_url=f"{GUIDELINES_URL}/#subcommands",
        )
    return None


def check_subcommand_structure(command: str) -> list[CheckResult]:
    """Check subcommand organization and discoverability."""
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    if not help_text:
        return []

    results = []
    has_subcommand_section = bool(
        re.search(
            r"(commands?|subcommands?|available|actions?):", help_text, re.IGNORECASE
        )
    )

    detected = _detect_subcommands(command)
    discovery_result = _check_subcommand_discovery(detected, has_subcommand_section)
    if discovery_result:
        results.append(discovery_result)

    if detected:
        for subcmd in detected[:2]:
            subcmd_help = run_command([command, subcmd, "--help"])
            if subcmd_help.exit_code == 0:
                results.append(
                    CheckResult(
                        name="subcommand_help",
                        description="Subcommands have their own help",
                        severity=Severity.PASS,
                        message=f"Subcommand '{subcmd}' has its own --help",
                        guideline_url=f"{GUIDELINES_URL}/#subcommands",
                    )
                )
                break

    return results


def check_description_quality(command: str) -> list[CheckResult]:
    """Check if the CLI has a clear, concise description."""
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    if not help_text:
        return []

    results = []
    lines = help_text.strip().split("\n")

    first_line = lines[0].strip() if lines else ""

    if first_line.lower().startswith("usage:"):
        if len(lines) > 1:
            for line in lines[1:5]:
                if line.strip() and not line.strip().startswith("-"):
                    first_line = line.strip()
                    break

    if len(first_line) < 10:
        results.append(
            CheckResult(
                name="description_present",
                description="Has clear description of purpose",
                severity=Severity.WARNING,
                message="No clear description found - what does this tool do?",
                guideline_url=f"{GUIDELINES_URL}/#help",
            )
        )
    elif len(first_line) > 100:
        results.append(
            CheckResult(
                name="description_present",
                description="Has clear description of purpose",
                severity=Severity.WARNING,
                message="Description may be too long for quick scanning",
                guideline_url=f"{GUIDELINES_URL}/#help",
            )
        )
    else:
        results.append(
            CheckResult(
                name="description_present",
                description="Has clear description of purpose",
                severity=Severity.PASS,
                message=f'Clear description: "{first_line[:60]}..."'
                if len(first_line) > 60
                else f'Clear description: "{first_line}"',
                guideline_url=f"{GUIDELINES_URL}/#help",
            )
        )

    return results


def check_error_suggestion(command: str) -> list[CheckResult]:
    """Check if errors suggest corrections or help."""
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "--halp"])
    error_text = output.stderr or output.stdout

    if not error_text:
        return []

    suggests_correction = any(
        phrase in error_text.lower()
        for phrase in [
            "did you mean",
            "similar",
            "perhaps you meant",
            "try",
            "--help",
            "see help",
            "usage:",
        ]
    )

    if suggests_correction:
        return [
            CheckResult(
                name="error_suggestion",
                description="Errors suggest corrections",
                severity=Severity.PASS,
                message="Error messages suggest corrections or point to help",
                guideline_url=f"{GUIDELINES_URL}/#errors",
            )
        ]

    return [
        CheckResult(
            name="error_suggestion",
            description="Errors suggest corrections",
            severity=Severity.WARNING,
            message="Errors don't suggest corrections - consider 'did you mean X?' or 'see --help'",
            guideline_url=f"{GUIDELINES_URL}/#errors",
        )
    ]


def check_positional_vs_flags(command: str) -> list[CheckResult]:
    """Check if the CLI prefers flags over ambiguous positional args."""
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    if not help_text:
        return []

    usage_match = re.search(r"usage:?\s*\S+\s+(.+)", help_text, re.IGNORECASE)
    if not usage_match:
        return []

    usage_line = usage_match.group(1)

    positional_count = len(re.findall(r"<[^>]+>|\[[A-Z_]+\]|[A-Z_]{2,}", usage_line))

    if positional_count > 3:
        return [
            CheckResult(
                name="flags_over_args",
                description="Prefers flags over positional args",
                severity=Severity.WARNING,
                message=f"Many positional args detected ({positional_count}) - flags are clearer for complex input",
                guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
            )
        ]

    return [
        CheckResult(
            name="flags_over_args",
            description="Prefers flags over positional args",
            severity=Severity.PASS,
            message="Reasonable number of positional arguments",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        )
    ]


def check_help_flags(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    results = []

    for flag in ["-h", "--help"]:
        output = run_command([command, flag])
        if output.exit_code == 0 and (output.stdout or output.stderr):
            content = output.stdout or output.stderr
            if len(content) > 50:
                results.append(
                    CheckResult(
                        name=f"help_{flag}",
                        description=f"Command responds to {flag}",
                        severity=Severity.PASS,
                        message=f"Help available via {flag}",
                        guideline_url=f"{GUIDELINES_URL}/#help",
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name=f"help_{flag}",
                        description=f"Command responds to {flag}",
                        severity=Severity.WARNING,
                        message=f"Help text for {flag} seems too brief ({len(content)} chars)",
                        guideline_url=f"{GUIDELINES_URL}/#help",
                    )
                )
        else:
            results.append(
                CheckResult(
                    name=f"help_{flag}",
                    description=f"Command responds to {flag}",
                    severity=Severity.ERROR,
                    message=f"No help available via {flag}",
                    details=output.stderr or "No output",
                    guideline_url=f"{GUIDELINES_URL}/#help",
                )
            )

    return results


def check_version_flag(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "--version"])
    if output.exit_code == 0 and output.stdout:
        return [
            CheckResult(
                name="version_flag",
                description="Command supports --version",
                severity=Severity.PASS,
                message=f"Version: {output.stdout.strip()[:80]}",
                guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
            )
        ]

    return [
        CheckResult(
            name="version_flag",
            description="Command supports --version",
            severity=Severity.WARNING,
            message="No --version flag support detected",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        )
    ]


def check_exit_codes(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    results = []

    help_output = run_command([command, "--help"])
    if help_output.exit_code == 0:
        results.append(
            CheckResult(
                name="exit_code_success",
                description="Returns 0 on successful help",
                severity=Severity.PASS,
                message="Returns exit code 0 for help",
                guideline_url=f"{GUIDELINES_URL}/#the-basics",
            )
        )
    else:
        results.append(
            CheckResult(
                name="exit_code_success",
                description="Returns 0 on successful help",
                severity=Severity.ERROR,
                message=f"Returns non-zero ({help_output.exit_code}) for --help",
                guideline_url=f"{GUIDELINES_URL}/#the-basics",
            )
        )

    bad_output = run_command([command, "--this-flag-should-not-exist-xyz"])
    if bad_output.exit_code != 0:
        results.append(
            CheckResult(
                name="exit_code_failure",
                description="Returns non-zero on failure",
                severity=Severity.PASS,
                message=f"Returns non-zero ({bad_output.exit_code}) on invalid input",
                guideline_url=f"{GUIDELINES_URL}/#the-basics",
            )
        )
    else:
        results.append(
            CheckResult(
                name="exit_code_failure",
                description="Returns non-zero on failure",
                severity=Severity.WARNING,
                message="Returns 0 even on invalid input",
                guideline_url=f"{GUIDELINES_URL}/#the-basics",
            )
        )

    return results


def check_no_color(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    env_with_no_color = os.environ.copy()
    env_with_no_color["NO_COLOR"] = "1"

    normal_output = run_command([command, "--help"])
    no_color_output = run_command([command, "--help"], env=env_with_no_color)

    has_ansi_normal = "\x1b[" in normal_output.stdout or "\x1b[" in normal_output.stderr
    has_ansi_no_color = (
        "\x1b[" in no_color_output.stdout or "\x1b[" in no_color_output.stderr
    )

    if has_ansi_normal and not has_ansi_no_color:
        return [
            CheckResult(
                name="no_color",
                description="Respects NO_COLOR environment variable",
                severity=Severity.PASS,
                message="Correctly disables color when NO_COLOR is set",
                guideline_url=f"{GUIDELINES_URL}/#output",
            )
        ]
    elif not has_ansi_normal:
        return [
            CheckResult(
                name="no_color",
                description="Respects NO_COLOR environment variable",
                severity=Severity.INFO,
                message="No color detected in output (may be fine)",
                guideline_url=f"{GUIDELINES_URL}/#output",
            )
        ]
    else:
        return [
            CheckResult(
                name="no_color",
                description="Respects NO_COLOR environment variable",
                severity=Severity.WARNING,
                message="Color output not disabled when NO_COLOR is set",
                guideline_url=f"{GUIDELINES_URL}/#output",
            )
        ]


def check_json_output(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    for flag in ["--json", "-j", "--format=json", "--output=json"]:
        output = run_command([command, flag])
        if output.exit_code == 0:
            return [
                CheckResult(
                    name="json_output",
                    description="Supports JSON output format",
                    severity=Severity.PASS,
                    message=f"Supports JSON output via {flag}",
                    guideline_url=f"{GUIDELINES_URL}/#output",
                )
            ]

    return [
        CheckResult(
            name="json_output",
            description="Supports JSON output format",
            severity=Severity.INFO,
            message="No JSON output flag detected (--json recommended)",
            guideline_url=f"{GUIDELINES_URL}/#output",
        )
    ]


def check_stderr_usage(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    bad_args_output = run_command([command, "--this-flag-should-not-exist-xyz"])

    if bad_args_output.stderr and not bad_args_output.stdout:
        return [
            CheckResult(
                name="stderr_usage",
                description="Errors sent to stderr",
                severity=Severity.PASS,
                message="Error messages correctly sent to stderr",
                guideline_url=f"{GUIDELINES_URL}/#the-basics",
            )
        ]
    elif bad_args_output.stdout and not bad_args_output.stderr:
        return [
            CheckResult(
                name="stderr_usage",
                description="Errors sent to stderr",
                severity=Severity.WARNING,
                message="Error messages may be going to stdout instead of stderr",
                guideline_url=f"{GUIDELINES_URL}/#the-basics",
            )
        ]

    return [
        CheckResult(
            name="stderr_usage",
            description="Errors sent to stderr",
            severity=Severity.INFO,
            message="Could not determine stderr usage",
            guideline_url=f"{GUIDELINES_URL}/#the-basics",
        )
    ]


def check_double_dash(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "--", "--help"])
    help_output = run_command([command, "--help"])

    if output.stdout != help_output.stdout or output.exit_code != help_output.exit_code:
        return [
            CheckResult(
                name="double_dash",
                description="Supports -- to end option parsing (POSIX)",
                severity=Severity.PASS,
                message="Correctly treats args after -- as operands",
                guideline_url="https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html",
            )
        ]

    return [
        CheckResult(
            name="double_dash",
            description="Supports -- to end option parsing (POSIX)",
            severity=Severity.INFO,
            message="Could not verify -- behavior",
            guideline_url="https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html",
        )
    ]


def check_stdin_dash(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "-"], stdin="test input")

    if output.exit_code == 0 or "stdin" in output.stderr.lower():
        return [
            CheckResult(
                name="stdin_dash",
                description="Supports - for stdin (POSIX)",
                severity=Severity.INFO,
                message="May support - for stdin",
                guideline_url="https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html",
            )
        ]

    return [
        CheckResult(
            name="stdin_dash",
            description="Supports - for stdin (POSIX)",
            severity=Severity.INFO,
            message="- operand behavior not detected",
            guideline_url="https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html",
        )
    ]


def check_help_content(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    results = []

    if not help_text:
        return results

    has_usage = bool(re.search(r"(usage|synopsis):", help_text, re.IGNORECASE))
    if has_usage:
        results.append(
            CheckResult(
                name="help_has_usage",
                description="Help includes usage pattern",
                severity=Severity.PASS,
                message="Help text includes usage/synopsis section",
                guideline_url=f"{GUIDELINES_URL}/#help",
            )
        )
    else:
        results.append(
            CheckResult(
                name="help_has_usage",
                description="Help includes usage pattern",
                severity=Severity.WARNING,
                message="No usage/synopsis section found in help",
                guideline_url=f"{GUIDELINES_URL}/#help",
            )
        )

    has_examples = bool(re.search(r"(example|e\.g\.)s?:", help_text, re.IGNORECASE))
    if has_examples:
        results.append(
            CheckResult(
                name="help_has_examples",
                description="Help includes examples",
                severity=Severity.PASS,
                message="Help text includes examples (highly valued!)",
                guideline_url=f"{GUIDELINES_URL}/#help",
            )
        )
    else:
        results.append(
            CheckResult(
                name="help_has_examples",
                description="Help includes examples",
                severity=Severity.WARNING,
                message="No examples found in help (users love examples!)",
                guideline_url=f"{GUIDELINES_URL}/#help",
            )
        )

    return results


def check_subcommand_help(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    output = run_command([command, "help"])

    if output.exit_code == 0 and len(output.stdout or output.stderr) > 50:
        return [
            CheckResult(
                name="help_subcommand",
                description="Supports 'help' subcommand",
                severity=Severity.PASS,
                message="'help' subcommand available (git-style)",
                guideline_url=f"{GUIDELINES_URL}/#help",
            )
        ]

    return [
        CheckResult(
            name="help_subcommand",
            description="Supports 'help' subcommand",
            severity=Severity.INFO,
            message="No 'help' subcommand (optional, git-style)",
            guideline_url=f"{GUIDELINES_URL}/#help",
        )
    ]


def check_quiet_flag(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    for flag in ["-q", "--quiet", "--silent"]:
        output = run_command([command, flag, "--help"])
        if output.exit_code == 0:
            return [
                CheckResult(
                    name="quiet_flag",
                    description="Supports quiet/silent mode",
                    severity=Severity.PASS,
                    message=f"Supports {flag} for reduced output",
                    guideline_url=f"{GUIDELINES_URL}/#output",
                )
            ]

    return [
        CheckResult(
            name="quiet_flag",
            description="Supports quiet/silent mode",
            severity=Severity.INFO,
            message="No -q/--quiet flag detected",
            guideline_url=f"{GUIDELINES_URL}/#output",
        )
    ]


def check_verbose_flag(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    for flag in ["-v", "--verbose", "-d", "--debug"]:
        help_output = run_command([command, "--help"])
        help_text = help_output.stdout or help_output.stderr
        if flag in help_text:
            return [
                CheckResult(
                    name="verbose_flag",
                    description="Supports verbose/debug mode",
                    severity=Severity.PASS,
                    message=f"Supports {flag} for verbose output",
                    guideline_url=f"{GUIDELINES_URL}/#output",
                )
            ]

    return [
        CheckResult(
            name="verbose_flag",
            description="Supports verbose/debug mode",
            severity=Severity.INFO,
            message="No -v/--verbose or -d/--debug flag detected",
            guideline_url=f"{GUIDELINES_URL}/#output",
        )
    ]


def _check_command_lowercase(command: str) -> CheckResult:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    if not command.islower():
        return CheckResult(
            name="command_lowercase",
            description="Command name is lowercase",
            severity=Severity.WARNING,
            message=f"Command '{command}' should be lowercase",
            guideline_url=f"{GUIDELINES_URL}/#naming",
        )
    return CheckResult(
        name="command_lowercase",
        description="Command name is lowercase",
        severity=Severity.PASS,
        message="Command name is lowercase",
        guideline_url=f"{GUIDELINES_URL}/#naming",
    )


def _check_command_length(command: str) -> CheckResult:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    cmd_len = len(command)
    if cmd_len > 14:
        return CheckResult(
            name="command_length",
            description="Command name is reasonably short",
            severity=Severity.WARNING,
            message=f"Command name '{command}' is long ({cmd_len} chars) - harder to type",
            guideline_url=f"{GUIDELINES_URL}/#naming",
        )
    elif cmd_len <= 6:
        return CheckResult(
            name="command_length",
            description="Command name is reasonably short",
            severity=Severity.PASS,
            message=f"Command name is short and easy to type ({cmd_len} chars)",
            guideline_url=f"{GUIDELINES_URL}/#naming",
        )
    return CheckResult(
        name="command_length",
        description="Command name is reasonably short",
        severity=Severity.PASS,
        message=f"Command name length is acceptable ({cmd_len} chars)",
        guideline_url=f"{GUIDELINES_URL}/#naming",
    )


def check_command_naming(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    results = [_check_command_lowercase(command), _check_command_length(command)]

    if "-" in command or "_" in command:
        results.append(
            CheckResult(
                name="command_no_delimiters",
                description="Command name avoids word delimiters",
                severity=Severity.WARNING,
                message="Command name contains hyphens/underscores - prefer single words",
                guideline_url=f"{GUIDELINES_URL}/#naming",
            )
        )

    return results


def check_input_flexibility(command: str) -> list[CheckResult]:
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    results = []
    help_output = run_command([command, "--help"])
    help_text = help_output.stdout or help_output.stderr

    if not help_text:
        return results

    has_equals_syntax = re.search(r"--\w+=", help_text)
    has_space_syntax = re.search(r"--\w+\s+[A-Z<\[]", help_text)

    if has_equals_syntax or has_space_syntax:
        results.append(
            CheckResult(
                name="flag_value_syntax",
                description="Clear flag value syntax",
                severity=Severity.PASS,
                message="Flag values syntax is documented",
                guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
            )
        )

    env_patterns = [r"[A-Z_]{2,}_[A-Z_]+", r"environment", r"env var"]
    has_env_config = any(re.search(p, help_text, re.IGNORECASE) for p in env_patterns)

    if has_env_config:
        results.append(
            CheckResult(
                name="env_config",
                description="Supports environment variable config",
                severity=Severity.PASS,
                message="Supports configuration via environment variables",
                guideline_url=f"{GUIDELINES_URL}/#environment-variables",
            )
        )

    return results


def check_negative_flags(command: str) -> list[CheckResult]:
    """Check for negative flags that suggest wrong defaults."""
    assert command is not None, "command must not be None"
    assert isinstance(command, str), "command must be a string"

    help_output = run_command([command, "--help"])
    help_text = help_output.stdout or help_output.stderr

    if not help_text:
        return []

    negative_patterns = [
        (r"--skip-(\w+)", "skip"),
        (r"--no-(\w+)", "no"),
        (r"--disable-(\w+)", "disable"),
        (r"--without-(\w+)", "without"),
        (r"--ignore-(\w+)", "ignore"),
    ]

    negative_flags = []
    for pattern, prefix in negative_patterns:
        matches = re.findall(pattern, help_text, re.IGNORECASE)
        for match in matches:
            negative_flags.append(f"--{prefix}-{match}")

    if not negative_flags:
        return []

    if len(negative_flags) > 3:
        return [
            CheckResult(
                name="negative_flags",
                description="Defaults should match common use",
                severity=Severity.WARNING,
                message=f"Many negative flags ({len(negative_flags)}) - consider if defaults are right for most users",
                details=f"Found: {', '.join(negative_flags[:5])}{'...' if len(negative_flags) > 5 else ''}",
                guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
            )
        ]

    return [
        CheckResult(
            name="negative_flags",
            description="Defaults should match common use",
            severity=Severity.INFO,
            message=f"Has negative flags: {', '.join(negative_flags)} - verify defaults match common use case",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        )
    ]


class UsabilityIssue(BaseModel):
    """A specific usability issue found in the CLI."""

    is_error: bool = Field(
        description="True if this is a serious problem, False if minor"
    )
    issue: str = Field(description="What the problem is - be specific")
    suggestion: str = Field(description="How to fix it - be actionable")
    guideline: str = Field(
        description="Which guideline this relates to: help, errors, arguments-and-flags, subcommands, output, or naming"
    )


class CLIAnalysis(BaseModel):
    """Holistic analysis of CLI usability."""

    issues: list[UsabilityIssue] = Field(description="All usability issues found")


CLI_ANALYZER_INSTRUCTIONS = """You are a CLI usability expert analyzing against clig.dev philosophy.

## PHILOSOPHY TO EVALUATE AGAINST

**Human-first design**: Is this CLI designed for humans, not just scripts? Modern CLIs should prioritize human usability.

**Ease of discovery**: Users shouldn't need docs to find basic features. Help should lead with examples, suggest next commands, make the common path obvious.

**Conversation as the norm**: CLIs are conversations. Errors should guide users, suggest corrections, not just fail cryptically.

**Saying just enough**: Not too much output (overwhelming), not too little (mysterious). The right amount of feedback.

**Empathy**: Does it feel like the authors care about users? Helpful error messages, clear descriptions, thoughtful defaults.

**Robustness**: Does it feel solid? Progress indicators for long operations? Graceful handling of edge cases?

## SPECIFIC GUIDELINES

**HELP TEXT**:
- First line should clearly explain what the tool does and WHY someone would use it
- Lead with examples showing common workflows
- Show most common flags first, not alphabetically
- Suggest related commands or next steps
- Be scannable with clear sections, not a wall of text

**NAMING**:
- Commands should be intuitive and guessable
- Consistent patterns (all verbs, or all nouns, not mixed)
- Standard flag meanings (-h=help, -v=verbose, -q=quiet, -o=output, -f=force)
- No ambiguous pairs (delete/remove, update/upgrade)

**ARGUMENTS & FLAGS**:
- Prefer flags to positional args (clearer, more flexible)
- Make the default the right thing for most users
- Negative flags (--no-X, --skip-X) suggest wrong defaults

**ERRORS**:
- Catch errors and rewrite for humans
- Signal-to-noise ratio is crucial
- Suggest how to fix, point to --help

## YOUR TASK

Find REAL usability issues. Be specific and actionable.

For each issue:
- is_error=True: Serious problem (unusable, confusing, violates conventions badly)
- is_error=False: Could be better (missing examples, unclear description, minor naming issues)
- issue: SPECIFIC problem ("'rm' command is ambiguous" not "naming could be better")
- suggestion: ACTIONABLE fix ("Rename to 'remove' or 'delete'" not "improve naming")
- guideline: help, errors, arguments-and-flags, subcommands, output, or naming

Don't invent problems. If the CLI is well-designed, return few or no issues."""


def get_cli_analyzer() -> Agent[None, CLIAnalysis]:
    assert Agent is not None, "Agent class must be available"
    assert CLIAnalysis is not None, "CLIAnalysis must be defined"

    return Agent(
        "anthropic:claude-sonnet-4-20250514",
        output_type=CLIAnalysis,
        instructions=CLI_ANALYZER_INSTRUCTIONS,
    )


async def check_cli_structure(command: str, help_text: str) -> list[CheckResult]:
    """Holistic AI analysis of CLI usability."""
    assert command is not None, "command must not be None"
    assert help_text is not None, "help_text must not be None"

    if not help_text or len(help_text) < 50:
        return []

    try:
        analyzer = get_cli_analyzer()
        result = await analyzer.run(
            f"Analyze the CLI '{command}' for usability issues:\n\n{help_text}"
        )
        analysis = result.output

        results = []
        guideline_urls = {
            "help": f"{GUIDELINES_URL}/#help",
            "errors": f"{GUIDELINES_URL}/#errors",
            "arguments-and-flags": f"{GUIDELINES_URL}/#arguments-and-flags",
            "subcommands": f"{GUIDELINES_URL}/#subcommands",
            "output": f"{GUIDELINES_URL}/#output",
            "naming": f"{GUIDELINES_URL}/#naming",
        }

        for issue in analysis.issues:
            url = guideline_urls.get(issue.guideline, GUIDELINES_URL)
            results.append(
                CheckResult(
                    name=f"ai_{issue.guideline}",
                    description=issue.issue,
                    severity=Severity.ERROR if issue.is_error else Severity.WARNING,
                    message=f"{issue.issue}: {issue.suggestion}",
                    guideline_url=url,
                )
            )

        return results
    except Exception as e:
        return [
            CheckResult(
                name="cli_analysis",
                description="CLI usability analysis",
                severity=Severity.INFO,
                message=f"Could not analyze: {e}",
                guideline_url=GUIDELINES_URL,
            )
        ]


class ErrorIssue(BaseModel):
    """A specific issue with error message quality."""

    is_error: bool = Field(description="True if serious, False if minor")
    issue: str = Field(description="What's wrong with the error message")
    suggestion: str = Field(description="How to improve it")


class ErrorAnalysis(BaseModel):
    """Analysis of CLI error messages."""

    issues: list[ErrorIssue] = Field(description="Issues found with error handling")


def get_error_analyzer() -> Agent[None, ErrorAnalysis]:
    assert Agent is not None, "Agent class must be available"
    assert ErrorAnalysis is not None, "ErrorAnalysis must be defined"

    return Agent(
        "anthropic:claude-sonnet-4-20250514",
        output_type=ErrorAnalysis,
        instructions="""Analyze this CLI error message for usability issues.

Good error messages should:
- Be human-readable (not stack traces or cryptic codes)
- Explain what went wrong
- Suggest how to fix it
- Point to --help or documentation

Find specific problems. Be actionable in suggestions.
If the error message is good, return no issues.""",
    )


async def check_error_quality(command: str, error_text: str) -> list[CheckResult]:
    """AI analysis of error message quality."""
    assert command is not None, "command must not be None"
    assert error_text is not None, "error_text must not be None"

    if not error_text or len(error_text) < 10:
        return []

    try:
        analyzer = get_error_analyzer()
        result = await analyzer.run(
            f"Analyze this error from '{command}':\n\n{error_text}"
        )
        analysis = result.output

        results = []
        for issue in analysis.issues:
            results.append(
                CheckResult(
                    name="ai_error",
                    description=issue.issue,
                    severity=Severity.ERROR if issue.is_error else Severity.WARNING,
                    message=f"{issue.issue}: {issue.suggestion}",
                    guideline_url=f"{GUIDELINES_URL}/#errors",
                )
            )

        return results
    except Exception as e:
        return [
            CheckResult(
                name="error_analysis",
                description="Error message analysis",
                severity=Severity.INFO,
                message=f"Could not analyze: {e}",
                guideline_url=f"{GUIDELINES_URL}/#errors",
            )
        ]


async def check_help_quality(command: str, help_text: str) -> list[CheckResult]:
    """Placeholder - merged into check_cli_structure."""
    assert command is not None, "command must not be None"
    assert help_text is not None, "help_text must not be None"

    return []
