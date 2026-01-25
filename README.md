# clint

CLI linter - analyze CLI tools against best practice guidelines.

Synthesizes recommendations from:

- [clig.dev](https://clig.dev) - Command Line Interface Guidelines
- [POSIX Utility Conventions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html)
- [12 Factor CLI Apps](https://medium.com/@jdxcode/12-factor-cli-apps-dd3c227a0e46) - Jeff Dickey
- [Heroku CLI Style Guide](https://devcenter.heroku.com/articles/cli-style-guide)

## Installation

```bash
git clone https://github.com/benomahony/clint
cd clint
uv sync
```

## Usage

```bash
# Full analysis (deterministic checks only)
uv run clint analyze git --skip-ai

# Full analysis with AI-powered checks (requires ANTHROPIC_API_KEY)
uv run clint analyze myapp

# JSON output for CI pipelines
uv run clint analyze myapp --json --skip-ai

# Run specific check
uv run clint check curl flags

# List all available checks
uv run clint list-checks
```

## Checks

### Surface-Level Checks

| Check | Description | Source |
|-------|-------------|--------|
| help | -h and --help flags work | clig.dev |
| version | --version flag exists | clig.dev |
| exit-codes | 0 on success, non-0 on failure | clig.dev |
| no-color | Respects NO_COLOR env var | no-color.org |
| json | --json output support | 12-factor CLI |
| stderr | Errors go to stderr | clig.dev |
| double-dash | -- ends option parsing | POSIX |
| quiet | -q/--quiet flag | clig.dev |
| verbose | -v/--verbose flag | clig.dev |

### Deep Structural Checks

| Check | Description | Source |
|-------|-------------|--------|
| naming | Command name lowercase, short, no delimiters | clig.dev |
| flags | Short+long forms, standard naming (-v, -o, -f), kebab-case | GNU/POSIX |
| subcommands | Discoverable in help, each has own --help | clig.dev |
| description | Clear one-line description of purpose | clig.dev |
| suggestions | Typos trigger "did you mean..." suggestions | clig.dev |
| positional | Flags preferred over many positional args | clig.dev |
| input | Env var config, flag syntax documented | 12-factor CLI |

### AI-Powered Analysis (requires ANTHROPIC_API_KEY)

| Check | What it checks |
|-------|----------------|
| help-quality | has_description, has_examples, has_usage, flag_descriptions, next_steps |
| error-quality | is_readable, explains_problem, suggests_fix, mentions_help |
| cli-structure | clear_description, usage_examples, subcommands_listed, flag_descriptions, related_commands, consistent_naming, standard_flags, no_ambiguous_names, scannable_help, errors_mention_help |

AI checks return true/false for each criterion plus specific, actionable suggestions.

## Example Output

```
$ clint analyze uv --skip-ai
                                  Analysis: uv
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check                ┃ Status ┃ Message                                      ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ help_-h              │   ✓    │ Help available via -h                        │
│ help_--help          │   ✓    │ Help available via --help                    │
│ version_flag         │   ✓    │ Version: uv 0.9.11                           │
│ flag_short_versions  │   ✓    │ Has both short (7) and long (18) flags       │
│ flag_naming          │   ✓    │ Flag names follow conventions                │
│ subcommand_discovery │   ✓    │ Help text lists available commands           │
│ description_present  │   ✓    │ Clear description: "An extremely fast..."    │
│ error_suggestion     │   ✓    │ Error messages suggest corrections           │
│ help_has_examples    │   ⚠    │ No examples found in help                    │
│                      │        │ → https://clig.dev/#help                     │
└──────────────────────┴────────┴──────────────────────────────────────────────┘

Summary: 22 passed, 1 warnings, 0 errors
```

Warnings and errors include links to the relevant documentation.

## CI Integration

```yaml
- name: Lint CLI
  run: |
    clint analyze mycli --skip-ai --json > clint-report.json
    # Exit code is non-zero if errors found
```
