# cliqa

Analyze CLI tools against [clig.dev](https://clig.dev) guidelines.

## Installation

```bash
uv tool install cliqa
# or
pip install cliqa
```

## Usage

Analyze any CLI command:

```bash
clint analyze ls
clint analyze git
clint analyze your-cli-tool
```

Run specific checks:

```bash
clint check ls help
clint check git version
```

List all available checks:

```bash
clint list-checks
```

## Features

- **No mocking**: Real integration tests with actual CLI commands
- **93% test coverage**: Comprehensive test suite
- **NASA05 compliance**: Defensive assertions throughout
- **clig.dev alignment**: Checks against modern CLI best practices

## Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/benomahony/cliqa
    rev: v0.1.1
    hooks:
      - id: cliqa
        args: [your-cli-tool]
```

Analyze multiple commands:

```yaml
repos:
  - repo: https://github.com/benomahony/cliqa
    rev: v0.1.1
    hooks:
      - id: cliqa
        name: Check main CLI
        args: [my-tool]
      - id: cliqa
        name: Check admin CLI
        args: [my-admin-tool]
```

Enable AI-powered analysis:

```yaml
repos:
  - repo: https://github.com/benomahony/cliqa
    rev: v0.1.1
    hooks:
      - id: cliqa
        args: [your-cli-tool, --ai]
```

This will analyze your CLI tool before each commit and fail if any errors are found.

## Development

```bash
# Install dependencies
uv sync --extra test

# Run tests
uv run pytest

# Run pre-commit checks
pre-commit run --all-files
```

## License

MIT
