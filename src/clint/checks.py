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
    result = {
        "flags": [],
        "subcommands": [],
        "positional_args": [],
        "has_usage": False,
        "has_examples": False,
        "has_description": False,
    }
    
    flag_pattern = r'(-[a-zA-Z]|--[a-zA-Z][-a-zA-Z0-9]*)'
    result["flags"] = list(set(re.findall(flag_pattern, help_text)))
    
    subcommand_patterns = [
        r'(?:commands?|subcommands?):\s*\n((?:\s+\w+.*\n)+)',
        r'(?:available commands?):\s*\n((?:\s+\w+.*\n)+)',
    ]
    for pattern in subcommand_patterns:
        match = re.search(pattern, help_text, re.IGNORECASE)
        if match:
            cmd_block = match.group(1)
            cmds = re.findall(r'^\s+(\w+)', cmd_block, re.MULTILINE)
            result["subcommands"] = cmds
            break
    
    result["has_usage"] = bool(re.search(r'(usage|synopsis):', help_text, re.IGNORECASE))
    result["has_examples"] = bool(re.search(r'(examples?|e\.g\.):', help_text, re.IGNORECASE))
    result["has_description"] = len(help_text.split('\n')[0].strip()) > 10
    
    return result


def check_flag_conventions(command: str) -> list[CheckResult]:
    """Check if flags follow standard naming conventions."""
    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    if not help_text:
        return []
    
    results = []
    parsed = parse_help_text(help_text)
    flags = parsed["flags"]
    
    short_flags = [f for f in flags if f.startswith('-') and not f.startswith('--')]
    long_flags = [f for f in flags if f.startswith('--')]
    
    if long_flags and not short_flags:
        results.append(CheckResult(
            name="flag_short_versions",
            description="Common flags have short versions",
            severity=Severity.WARNING,
            message="No short flags detected - consider adding -h, -v, etc.",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        ))
    elif short_flags and long_flags:
        results.append(CheckResult(
            name="flag_short_versions",
            description="Common flags have short versions",
            severity=Severity.PASS,
            message=f"Has both short ({len(short_flags)}) and long ({len(long_flags)}) flags",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        ))
    
    nonstandard = []
    for flag in flags:
        if flag in STANDARD_FLAGS:
            continue
        if flag.startswith('--'):
            name = flag[2:]
            if '_' in name:
                nonstandard.append(f"{flag} (use kebab-case: --{name.replace('_', '-')})")
            elif name.isupper():
                nonstandard.append(f"{flag} (use lowercase)")
    
    if nonstandard:
        results.append(CheckResult(
            name="flag_naming",
            description="Flags follow naming conventions",
            severity=Severity.WARNING,
            message=f"Non-standard flag names: {', '.join(nonstandard[:3])}",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        ))
    else:
        results.append(CheckResult(
            name="flag_naming",
            description="Flags follow naming conventions",
            severity=Severity.PASS,
            message="Flag names follow conventions (lowercase, kebab-case)",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        ))
    
    return results


def check_subcommand_structure(command: str) -> list[CheckResult]:
    """Check subcommand organization and discoverability."""
    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    if not help_text:
        return []
    
    results = []
    parsed = parse_help_text(help_text)
    
    has_subcommand_section = bool(re.search(
        r'(commands?|subcommands?|available|actions?):', 
        help_text, 
        re.IGNORECASE
    ))
    
    test_cmds = ["list", "help", "version", "status", "info", "get", "create", "delete"]
    detected_subcommands = []
    for cmd in test_cmds:
        test_output = run_command([command, cmd, "--help"], timeout=2.0)
        if test_output.exit_code == 0 and len(test_output.stdout or test_output.stderr) > 20:
            detected_subcommands.append(cmd)
    
    if detected_subcommands and not has_subcommand_section:
        results.append(CheckResult(
            name="subcommand_discovery",
            description="Subcommands are discoverable in help",
            severity=Severity.WARNING,
            message=f"Has subcommands ({', '.join(detected_subcommands)}) but help doesn't list them clearly",
            guideline_url=f"{GUIDELINES_URL}/#subcommands",
        ))
    elif has_subcommand_section:
        results.append(CheckResult(
            name="subcommand_discovery",
            description="Subcommands are discoverable in help",
            severity=Severity.PASS,
            message="Help text lists available commands/subcommands",
            guideline_url=f"{GUIDELINES_URL}/#subcommands",
        ))
    
    if detected_subcommands:
        for subcmd in detected_subcommands[:2]:
            subcmd_help = run_command([command, subcmd, "--help"])
            if subcmd_help.exit_code == 0:
                results.append(CheckResult(
                    name="subcommand_help",
                    description="Subcommands have their own help",
                    severity=Severity.PASS,
                    message=f"Subcommand '{subcmd}' has its own --help",
                    guideline_url=f"{GUIDELINES_URL}/#subcommands",
                ))
                break
    
    return results


def check_description_quality(command: str) -> list[CheckResult]:
    """Check if the CLI has a clear, concise description."""
    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    if not help_text:
        return []
    
    results = []
    lines = help_text.strip().split('\n')
    
    first_line = lines[0].strip() if lines else ""
    
    if first_line.lower().startswith('usage:'):
        if len(lines) > 1:
            for line in lines[1:5]:
                if line.strip() and not line.strip().startswith('-'):
                    first_line = line.strip()
                    break
    
    if len(first_line) < 10:
        results.append(CheckResult(
            name="description_present",
            description="Has clear description of purpose",
            severity=Severity.WARNING,
            message="No clear description found - what does this tool do?",
            guideline_url=f"{GUIDELINES_URL}/#help",
        ))
    elif len(first_line) > 100:
        results.append(CheckResult(
            name="description_present",
            description="Has clear description of purpose",
            severity=Severity.WARNING,
            message="Description may be too long for quick scanning",
            guideline_url=f"{GUIDELINES_URL}/#help",
        ))
    else:
        results.append(CheckResult(
            name="description_present",
            description="Has clear description of purpose",
            severity=Severity.PASS,
            message=f"Clear description: \"{first_line[:60]}...\"" if len(first_line) > 60 else f"Clear description: \"{first_line}\"",
            guideline_url=f"{GUIDELINES_URL}/#help",
        ))
    
    return results


def check_error_suggestion(command: str) -> list[CheckResult]:
    """Check if errors suggest corrections or help."""
    output = run_command([command, "--halp"])
    error_text = output.stderr or output.stdout
    
    if not error_text:
        return []
    
    suggests_correction = any(phrase in error_text.lower() for phrase in [
        "did you mean",
        "similar",
        "perhaps you meant",
        "try",
        "--help",
        "see help",
        "usage:",
    ])
    
    if suggests_correction:
        return [CheckResult(
            name="error_suggestion",
            description="Errors suggest corrections",
            severity=Severity.PASS,
            message="Error messages suggest corrections or point to help",
            guideline_url=f"{GUIDELINES_URL}/#errors",
        )]
    
    return [CheckResult(
        name="error_suggestion",
        description="Errors suggest corrections",
        severity=Severity.WARNING,
        message="Errors don't suggest corrections - consider 'did you mean X?' or 'see --help'",
        guideline_url=f"{GUIDELINES_URL}/#errors",
    )]


def check_positional_vs_flags(command: str) -> list[CheckResult]:
    """Check if the CLI prefers flags over ambiguous positional args."""
    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    if not help_text:
        return []
    
    usage_match = re.search(r'usage:?\s*\S+\s+(.+)', help_text, re.IGNORECASE)
    if not usage_match:
        return []
    
    usage_line = usage_match.group(1)
    
    positional_count = len(re.findall(r'<[^>]+>|\[[A-Z_]+\]|[A-Z_]{2,}', usage_line))
    
    if positional_count > 3:
        return [CheckResult(
            name="flags_over_args",
            description="Prefers flags over positional args",
            severity=Severity.WARNING,
            message=f"Many positional args detected ({positional_count}) - flags are clearer for complex input",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        )]
    
    return [CheckResult(
        name="flags_over_args",
        description="Prefers flags over positional args",
        severity=Severity.PASS,
        message="Reasonable number of positional arguments",
        guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
    )]


def check_help_flags(command: str) -> list[CheckResult]:
    results = []
    
    for flag in ["-h", "--help"]:
        output = run_command([command, flag])
        if output.exit_code == 0 and (output.stdout or output.stderr):
            content = output.stdout or output.stderr
            if len(content) > 50:
                results.append(CheckResult(
                    name=f"help_{flag}",
                    description=f"Command responds to {flag}",
                    severity=Severity.PASS,
                    message=f"Help available via {flag}",
                    guideline_url=f"{GUIDELINES_URL}/#help",
                ))
            else:
                results.append(CheckResult(
                    name=f"help_{flag}",
                    description=f"Command responds to {flag}",
                    severity=Severity.WARNING,
                    message=f"Help text for {flag} seems too brief ({len(content)} chars)",
                    guideline_url=f"{GUIDELINES_URL}/#help",
                ))
        else:
            results.append(CheckResult(
                name=f"help_{flag}",
                description=f"Command responds to {flag}",
                severity=Severity.ERROR,
                message=f"No help available via {flag}",
                details=output.stderr or "No output",
                guideline_url=f"{GUIDELINES_URL}/#help",
            ))
    
    return results


def check_version_flag(command: str) -> list[CheckResult]:
    output = run_command([command, "--version"])
    if output.exit_code == 0 and output.stdout:
        return [CheckResult(
            name="version_flag",
            description="Command supports --version",
            severity=Severity.PASS,
            message=f"Version: {output.stdout.strip()[:80]}",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        )]
    
    return [CheckResult(
        name="version_flag",
        description="Command supports --version",
        severity=Severity.WARNING,
        message="No --version flag support detected",
        guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
    )]


def check_exit_codes(command: str) -> list[CheckResult]:
    results = []
    
    help_output = run_command([command, "--help"])
    if help_output.exit_code == 0:
        results.append(CheckResult(
            name="exit_code_success",
            description="Returns 0 on successful help",
            severity=Severity.PASS,
            message="Returns exit code 0 for help",
            guideline_url=f"{GUIDELINES_URL}/#the-basics",
        ))
    else:
        results.append(CheckResult(
            name="exit_code_success",
            description="Returns 0 on successful help",
            severity=Severity.ERROR,
            message=f"Returns non-zero ({help_output.exit_code}) for --help",
            guideline_url=f"{GUIDELINES_URL}/#the-basics",
        ))
    
    bad_output = run_command([command, "--this-flag-should-not-exist-xyz"])
    if bad_output.exit_code != 0:
        results.append(CheckResult(
            name="exit_code_failure",
            description="Returns non-zero on failure",
            severity=Severity.PASS,
            message=f"Returns non-zero ({bad_output.exit_code}) on invalid input",
            guideline_url=f"{GUIDELINES_URL}/#the-basics",
        ))
    else:
        results.append(CheckResult(
            name="exit_code_failure",
            description="Returns non-zero on failure",
            severity=Severity.WARNING,
            message="Returns 0 even on invalid input",
            guideline_url=f"{GUIDELINES_URL}/#the-basics",
        ))
    
    return results


def check_no_color(command: str) -> list[CheckResult]:
    env_with_no_color = os.environ.copy()
    env_with_no_color["NO_COLOR"] = "1"
    
    normal_output = run_command([command, "--help"])
    no_color_output = run_command([command, "--help"], env=env_with_no_color)
    
    has_ansi_normal = "\x1b[" in normal_output.stdout or "\x1b[" in normal_output.stderr
    has_ansi_no_color = "\x1b[" in no_color_output.stdout or "\x1b[" in no_color_output.stderr
    
    if has_ansi_normal and not has_ansi_no_color:
        return [CheckResult(
            name="no_color",
            description="Respects NO_COLOR environment variable",
            severity=Severity.PASS,
            message="Correctly disables color when NO_COLOR is set",
            guideline_url=f"{GUIDELINES_URL}/#output",
        )]
    elif not has_ansi_normal:
        return [CheckResult(
            name="no_color",
            description="Respects NO_COLOR environment variable",
            severity=Severity.INFO,
            message="No color detected in output (may be fine)",
            guideline_url=f"{GUIDELINES_URL}/#output",
        )]
    else:
        return [CheckResult(
            name="no_color",
            description="Respects NO_COLOR environment variable",
            severity=Severity.WARNING,
            message="Color output not disabled when NO_COLOR is set",
            guideline_url=f"{GUIDELINES_URL}/#output",
        )]


def check_json_output(command: str) -> list[CheckResult]:
    for flag in ["--json", "-j", "--format=json", "--output=json"]:
        output = run_command([command, flag])
        if output.exit_code == 0:
            return [CheckResult(
                name="json_output",
                description="Supports JSON output format",
                severity=Severity.PASS,
                message=f"Supports JSON output via {flag}",
                guideline_url=f"{GUIDELINES_URL}/#output",
            )]
    
    return [CheckResult(
        name="json_output",
        description="Supports JSON output format",
        severity=Severity.INFO,
        message="No JSON output flag detected (--json recommended)",
        guideline_url=f"{GUIDELINES_URL}/#output",
    )]


def check_stderr_usage(command: str) -> list[CheckResult]:
    bad_args_output = run_command([command, "--this-flag-should-not-exist-xyz"])
    
    if bad_args_output.stderr and not bad_args_output.stdout:
        return [CheckResult(
            name="stderr_usage",
            description="Errors sent to stderr",
            severity=Severity.PASS,
            message="Error messages correctly sent to stderr",
            guideline_url=f"{GUIDELINES_URL}/#the-basics",
        )]
    elif bad_args_output.stdout and not bad_args_output.stderr:
        return [CheckResult(
            name="stderr_usage",
            description="Errors sent to stderr",
            severity=Severity.WARNING,
            message="Error messages may be going to stdout instead of stderr",
            guideline_url=f"{GUIDELINES_URL}/#the-basics",
        )]
    
    return [CheckResult(
        name="stderr_usage",
        description="Errors sent to stderr",
        severity=Severity.INFO,
        message="Could not determine stderr usage",
        guideline_url=f"{GUIDELINES_URL}/#the-basics",
    )]


def check_double_dash(command: str) -> list[CheckResult]:
    output = run_command([command, "--", "--help"])
    help_output = run_command([command, "--help"])
    
    if output.stdout != help_output.stdout or output.exit_code != help_output.exit_code:
        return [CheckResult(
            name="double_dash",
            description="Supports -- to end option parsing (POSIX)",
            severity=Severity.PASS,
            message="Correctly treats args after -- as operands",
            guideline_url="https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html",
        )]
    
    return [CheckResult(
        name="double_dash",
        description="Supports -- to end option parsing (POSIX)",
        severity=Severity.INFO,
        message="Could not verify -- behavior",
        guideline_url="https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html",
    )]


def check_stdin_dash(command: str) -> list[CheckResult]:
    output = run_command([command, "-"], stdin="test input")
    
    if output.exit_code == 0 or "stdin" in output.stderr.lower():
        return [CheckResult(
            name="stdin_dash",
            description="Supports - for stdin (POSIX)",
            severity=Severity.INFO,
            message="May support - for stdin",
            guideline_url="https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html",
        )]
    
    return [CheckResult(
        name="stdin_dash",
        description="Supports - for stdin (POSIX)",
        severity=Severity.INFO,
        message="- operand behavior not detected",
        guideline_url="https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html",
    )]


def check_help_content(command: str) -> list[CheckResult]:
    output = run_command([command, "--help"])
    help_text = output.stdout or output.stderr
    results = []
    
    if not help_text:
        return results
    
    has_usage = bool(re.search(r"(usage|synopsis):", help_text, re.IGNORECASE))
    if has_usage:
        results.append(CheckResult(
            name="help_has_usage",
            description="Help includes usage pattern",
            severity=Severity.PASS,
            message="Help text includes usage/synopsis section",
            guideline_url=f"{GUIDELINES_URL}/#help",
        ))
    else:
        results.append(CheckResult(
            name="help_has_usage",
            description="Help includes usage pattern",
            severity=Severity.WARNING,
            message="No usage/synopsis section found in help",
            guideline_url=f"{GUIDELINES_URL}/#help",
        ))
    
    has_examples = bool(re.search(r"(example|e\.g\.)s?:", help_text, re.IGNORECASE))
    if has_examples:
        results.append(CheckResult(
            name="help_has_examples",
            description="Help includes examples",
            severity=Severity.PASS,
            message="Help text includes examples (highly valued!)",
            guideline_url=f"{GUIDELINES_URL}/#help",
        ))
    else:
        results.append(CheckResult(
            name="help_has_examples",
            description="Help includes examples",
            severity=Severity.WARNING,
            message="No examples found in help (users love examples!)",
            guideline_url=f"{GUIDELINES_URL}/#help",
        ))
    
    return results


def check_subcommand_help(command: str) -> list[CheckResult]:
    output = run_command([command, "help"])
    
    if output.exit_code == 0 and len(output.stdout or output.stderr) > 50:
        return [CheckResult(
            name="help_subcommand",
            description="Supports 'help' subcommand",
            severity=Severity.PASS,
            message="'help' subcommand available (git-style)",
            guideline_url=f"{GUIDELINES_URL}/#help",
        )]
    
    return [CheckResult(
        name="help_subcommand",
        description="Supports 'help' subcommand",
        severity=Severity.INFO,
        message="No 'help' subcommand (optional, git-style)",
        guideline_url=f"{GUIDELINES_URL}/#help",
    )]


def check_quiet_flag(command: str) -> list[CheckResult]:
    for flag in ["-q", "--quiet", "--silent"]:
        output = run_command([command, flag, "--help"])
        if output.exit_code == 0:
            return [CheckResult(
                name="quiet_flag",
                description="Supports quiet/silent mode",
                severity=Severity.PASS,
                message=f"Supports {flag} for reduced output",
                guideline_url=f"{GUIDELINES_URL}/#output",
            )]
    
    return [CheckResult(
        name="quiet_flag",
        description="Supports quiet/silent mode",
        severity=Severity.INFO,
        message="No -q/--quiet flag detected",
        guideline_url=f"{GUIDELINES_URL}/#output",
    )]


def check_verbose_flag(command: str) -> list[CheckResult]:
    for flag in ["-v", "--verbose", "-d", "--debug"]:
        help_output = run_command([command, "--help"])
        help_text = help_output.stdout or help_output.stderr
        if flag in help_text:
            return [CheckResult(
                name="verbose_flag",
                description="Supports verbose/debug mode",
                severity=Severity.PASS,
                message=f"Supports {flag} for verbose output",
                guideline_url=f"{GUIDELINES_URL}/#output",
            )]
    
    return [CheckResult(
        name="verbose_flag",
        description="Supports verbose/debug mode",
        severity=Severity.INFO,
        message="No -v/--verbose or -d/--debug flag detected",
        guideline_url=f"{GUIDELINES_URL}/#output",
    )]


def check_command_naming(command: str) -> list[CheckResult]:
    results = []
    
    if not command.islower():
        results.append(CheckResult(
            name="command_lowercase",
            description="Command name is lowercase",
            severity=Severity.WARNING,
            message=f"Command '{command}' should be lowercase",
            guideline_url=f"{GUIDELINES_URL}/#naming",
        ))
    else:
        results.append(CheckResult(
            name="command_lowercase",
            description="Command name is lowercase",
            severity=Severity.PASS,
            message="Command name is lowercase",
            guideline_url=f"{GUIDELINES_URL}/#naming",
        ))
    
    if len(command) > 14:
        results.append(CheckResult(
            name="command_length",
            description="Command name is reasonably short",
            severity=Severity.WARNING,
            message=f"Command name '{command}' is long ({len(command)} chars) - harder to type",
            guideline_url=f"{GUIDELINES_URL}/#naming",
        ))
    elif len(command) <= 6:
        results.append(CheckResult(
            name="command_length",
            description="Command name is reasonably short",
            severity=Severity.PASS,
            message=f"Command name is short and easy to type ({len(command)} chars)",
            guideline_url=f"{GUIDELINES_URL}/#naming",
        ))
    else:
        results.append(CheckResult(
            name="command_length",
            description="Command name is reasonably short",
            severity=Severity.PASS,
            message=f"Command name length is acceptable ({len(command)} chars)",
            guideline_url=f"{GUIDELINES_URL}/#naming",
        ))
    
    if "-" in command or "_" in command:
        results.append(CheckResult(
            name="command_no_delimiters",
            description="Command name avoids word delimiters",
            severity=Severity.WARNING,
            message="Command name contains hyphens/underscores - prefer single words",
            guideline_url=f"{GUIDELINES_URL}/#naming",
        ))
    
    return results
    
    return results


def check_input_flexibility(command: str) -> list[CheckResult]:
    results = []
    help_output = run_command([command, "--help"])
    help_text = help_output.stdout or help_output.stderr
    
    if not help_text:
        return results
    
    has_equals_syntax = re.search(r"--\w+=", help_text)
    has_space_syntax = re.search(r"--\w+\s+[A-Z<\[]", help_text)
    
    if has_equals_syntax or has_space_syntax:
        results.append(CheckResult(
            name="flag_value_syntax",
            description="Clear flag value syntax",
            severity=Severity.PASS,
            message="Flag values syntax is documented",
            guideline_url=f"{GUIDELINES_URL}/#arguments-and-flags",
        ))
    
    env_patterns = [r"[A-Z_]{2,}_[A-Z_]+", r"environment", r"env var"]
    has_env_config = any(re.search(p, help_text, re.IGNORECASE) for p in env_patterns)
    
    if has_env_config:
        results.append(CheckResult(
            name="env_config",
            description="Supports environment variable config",
            severity=Severity.PASS,
            message="Supports configuration via environment variables",
            guideline_url=f"{GUIDELINES_URL}/#environment-variables",
        ))
    
    return results


class CLIStructureAnalysis(BaseModel):
    """Concrete checks for CLI design quality."""
    
    has_clear_description: bool = Field(description="First line clearly explains what the tool does")
    has_usage_examples: bool = Field(description="Help includes concrete usage examples")
    subcommands_listed: bool = Field(description="If has subcommands, they are listed in help")
    flags_have_descriptions: bool = Field(description="Flags have clear descriptions, not just names")
    related_commands_suggested: bool = Field(description="Help suggests related commands or next steps")
    consistent_naming_pattern: bool = Field(description="Commands/flags follow a consistent pattern (all verbs, all nouns, etc)")
    standard_flags_used_correctly: bool = Field(description="-h=help, -v=verbose/version, -q=quiet, -o=output, -f=force")
    no_ambiguous_commands: bool = Field(description="No confusing pairs like delete/remove or update/upgrade")
    help_scannable: bool = Field(description="Help is organized with sections, not a wall of text")
    errors_mention_help: bool = Field(description="Error messages point to --help or relevant docs")
    
    suggestions: list[str] = Field(description="Specific, actionable improvements")


def get_structure_analyzer() -> Agent[None, CLIStructureAnalysis]:
    return Agent(
        "anthropic:claude-sonnet-4-20250514",
        output_type=CLIStructureAnalysis,
        instructions="""Analyze CLI help text for specific design issues. Answer each boolean honestly.

For suggestions, be SPECIFIC and ACTIONABLE:
- BAD: "improve naming"
- GOOD: "rename 'rm' to 'remove' for clarity"
- BAD: "add examples"  
- GOOD: "add example showing how to filter by date: 'mycli list --since 2024-01-01'"

Only include suggestions for things that are actually problems.""",
    )


async def check_cli_structure(command: str, help_text: str) -> list[CheckResult]:
    """Concrete AI checks for CLI structure."""
    if not help_text or len(help_text) < 50:
        return []

    try:
        analyzer = get_structure_analyzer()
        result = await analyzer.run(
            f"Analyze the CLI help for '{command}':\n\n{help_text}"
        )
        analysis = result.output
        
        results = []
        
        checks = [
            ("clear_description", "Has clear description of purpose", analysis.has_clear_description),
            ("usage_examples", "Help includes usage examples", analysis.has_usage_examples),
            ("subcommands_listed", "Subcommands listed in help", analysis.subcommands_listed),
            ("flag_descriptions", "Flags have clear descriptions", analysis.flags_have_descriptions),
            ("related_commands", "Suggests related commands/next steps", analysis.related_commands_suggested),
            ("consistent_naming", "Consistent naming pattern", analysis.consistent_naming_pattern),
            ("standard_flags", "Standard flag meanings (-h, -v, -q, -o)", analysis.standard_flags_used_correctly),
            ("no_ambiguous_names", "No ambiguous command names", analysis.no_ambiguous_commands),
            ("scannable_help", "Help is scannable (sections, not wall of text)", analysis.help_scannable),
            ("errors_mention_help", "Errors point to --help", analysis.errors_mention_help),
        ]
        
        for name, desc, passed in checks:
            results.append(CheckResult(
                name=name,
                description=desc,
                severity=Severity.PASS if passed else Severity.WARNING,
                message=desc if passed else f"Missing: {desc.lower()}",
                guideline_url=f"{GUIDELINES_URL}/#help",
            ))
        
        if analysis.suggestions:
            for i, suggestion in enumerate(analysis.suggestions[:5]):
                results.append(CheckResult(
                    name=f"suggestion_{i+1}",
                    description="Improvement suggestion",
                    severity=Severity.INFO,
                    message=suggestion,
                    guideline_url=f"{GUIDELINES_URL}",
                ))
        
        return results
    except Exception as e:
        return [CheckResult(
            name="cli_structure",
            description="CLI structure analysis",
            severity=Severity.INFO,
            message=f"Could not analyze CLI structure: {e}",
            guideline_url=f"{GUIDELINES_URL}",
        )]


class HelpTextAnalysis(BaseModel):
    has_description: bool = Field(description="First line clearly explains what the command does")
    has_examples: bool = Field(description="Includes concrete usage examples")
    has_usage_pattern: bool = Field(description="Shows usage/synopsis pattern")
    has_flag_descriptions: bool = Field(description="Flags have descriptions, not just listed")
    suggests_next_steps: bool = Field(description="Mentions related commands or what to do next")
    
    suggestions: list[str] = Field(description="Specific actionable improvements - be concrete, not vague")


def get_help_analyzer() -> Agent[None, HelpTextAnalysis]:
    return Agent(
        "anthropic:claude-sonnet-4-20250514",
        output_type=HelpTextAnalysis,
        instructions="""Analyze CLI help text. Answer each boolean honestly based on what you see.

For suggestions, be SPECIFIC:
- BAD: "add more examples"
- GOOD: "add example showing --format flag: 'mycli export --format json data.csv'"
- BAD: "improve descriptions"
- GOOD: "describe what --recursive actually does (e.g., 'process all files in subdirectories')"

Only suggest things that are actually missing or problematic.""",
    )


async def check_help_quality(command: str, help_text: str) -> list[CheckResult]:
    if not help_text or len(help_text) < 20:
        return [CheckResult(
            name="help_quality",
            description="Help text quality analysis",
            severity=Severity.WARNING,
            message="Help text too brief to analyze",
            guideline_url=f"{GUIDELINES_URL}/#help",
        )]

    try:
        analyzer = get_help_analyzer()
        result = await analyzer.run(f"Analyze this help text for '{command}':\n\n{help_text}")
        analysis = result.output
        
        results = []
        
        checks = [
            ("ai_has_description", "Has clear description", analysis.has_description),
            ("ai_has_examples", "Includes usage examples", analysis.has_examples),
            ("ai_has_usage", "Shows usage pattern", analysis.has_usage_pattern),
            ("ai_flag_descriptions", "Flags have descriptions", analysis.has_flag_descriptions),
            ("ai_next_steps", "Suggests next steps", analysis.suggests_next_steps),
        ]
        
        for name, desc, passed in checks:
            results.append(CheckResult(
                name=name,
                description=desc,
                severity=Severity.PASS if passed else Severity.WARNING,
                message=desc if passed else f"Missing: {desc.lower()}",
                guideline_url=f"{GUIDELINES_URL}/#help",
            ))
        
        for i, suggestion in enumerate(analysis.suggestions[:3]):
            results.append(CheckResult(
                name=f"help_suggestion_{i+1}",
                description="Help improvement",
                severity=Severity.INFO,
                message=suggestion,
                guideline_url=f"{GUIDELINES_URL}/#help",
            ))
        
        return results
    except Exception as e:
        return [CheckResult(
            name="help_quality",
            description="Help text quality analysis",
            severity=Severity.INFO,
            message=f"Could not analyze help quality: {e}",
            guideline_url=f"{GUIDELINES_URL}/#help",
        )]


class ErrorAnalysis(BaseModel):
    is_human_readable: bool = Field(description="Error is plain English, not a stack trace or error code")
    explains_problem: bool = Field(description="Error says what went wrong")
    suggests_fix: bool = Field(description="Error suggests how to fix or what to try")
    mentions_help: bool = Field(description="Error points to --help or documentation")
    
    suggestions: list[str] = Field(description="Specific improvements for this error message")


def get_error_analyzer() -> Agent[None, ErrorAnalysis]:
    return Agent(
        "anthropic:claude-sonnet-4-20250514",
        output_type=ErrorAnalysis,
        instructions="""Analyze this CLI error message. Answer each boolean based on what you see.

For suggestions, be specific:
- BAD: "be more helpful"
- GOOD: "add 'Did you mean --help?' when user types --hepl"
- GOOD: "include the valid options when an invalid option is given"

Only suggest concrete improvements.""",
    )


async def check_error_quality(command: str, error_text: str) -> list[CheckResult]:
    if not error_text or len(error_text) < 10:
        return [CheckResult(
            name="error_quality",
            description="Error message quality",
            severity=Severity.INFO,
            message="No error output to analyze",
            guideline_url=f"{GUIDELINES_URL}/#errors",
        )]

    try:
        analyzer = get_error_analyzer()
        result = await analyzer.run(
            f"Analyze this error message from '{command}':\n\n{error_text}"
        )
        analysis = result.output
        
        results = []
        
        checks = [
            ("error_readable", "Error is human readable", analysis.is_human_readable),
            ("error_explains", "Error explains the problem", analysis.explains_problem),
            ("error_suggests_fix", "Error suggests how to fix", analysis.suggests_fix),
            ("error_mentions_help", "Error points to --help", analysis.mentions_help),
        ]
        
        for name, desc, passed in checks:
            results.append(CheckResult(
                name=name,
                description=desc,
                severity=Severity.PASS if passed else Severity.WARNING,
                message=desc if passed else f"Missing: {desc.lower()}",
                guideline_url=f"{GUIDELINES_URL}/#errors",
            ))
        
        for i, suggestion in enumerate(analysis.suggestions[:2]):
            results.append(CheckResult(
                name=f"error_suggestion_{i+1}",
                description="Error improvement",
                severity=Severity.INFO,
                message=suggestion,
                guideline_url=f"{GUIDELINES_URL}/#errors",
            ))
        
        return results
    except Exception as e:
        return [CheckResult(
            name="error_quality",
            description="Error message quality",
            severity=Severity.INFO,
            message=f"Could not analyze error quality: {e}",
            guideline_url=f"{GUIDELINES_URL}/#errors",
        )]
