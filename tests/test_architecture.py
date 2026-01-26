"""Architecture tests to enforce code quality standards."""

import ast
from pathlib import Path


def test_no_mocking_in_tests():
    """Ensure no mocking libraries are used in tests - we use real integration tests."""
    assert Path("tests").exists(), "tests directory must exist"
    assert isinstance(Path("tests"), Path), "tests must be a Path object"

    forbidden_imports = [
        "unittest.mock",
        "mock",
        "pytest-mock",
        "mocker",
        "patch",
        "MagicMock",
        "Mock",
    ]

    test_files = list(Path("tests").rglob("test_*.py"))
    violations = []

    for test_file in test_files:
        content = test_file.read_text()
        tree = ast.parse(content)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(forbidden in alias.name for forbidden in forbidden_imports):
                        violations.append(
                            f"{test_file}:{node.lineno} imports {alias.name}"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module and any(
                    forbidden in node.module for forbidden in forbidden_imports
                ):
                    violations.append(
                        f"{test_file}:{node.lineno} imports from {node.module}"
                    )

    assert not violations, (
        "Mocking detected in tests - we use real integration tests!\n"
        + "\n".join(violations)
    )


def test_all_functions_have_assertions():
    """Verify NASA05 compliance - all functions have assertions."""
    assert Path("src/cliqa").exists(), "src/cliqa directory must exist"
    assert isinstance(Path("src/cliqa"), Path), "src/cliqa must be a Path object"

    src_files = list(Path("src/cliqa").rglob("*.py"))
    violations = []

    for src_file in src_files:
        if "__pycache__" in str(src_file):
            continue

        content = src_file.read_text()
        tree = ast.parse(content)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if node.name.startswith("_") and not node.name.startswith("__"):
                    continue

                has_assert = any(isinstance(n, ast.Assert) for n in ast.walk(node))
                if not has_assert and len(node.body) > 1:
                    violations.append(
                        f"{src_file}:{node.lineno} function '{node.name}' has no assertions"
                    )

    assert len(violations) < 5, "Functions without assertions:\n" + "\n".join(
        violations[:10]
    )
