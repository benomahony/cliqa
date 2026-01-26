"""Tests for CLI AI functionality."""

import asyncio
import os
import pytest
from cliqa.cli import run_all_checks
from cliqa.models import AnalysisReport


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="Requires ANTHROPIC_API_KEY environment variable",
)
async def test_run_all_checks_with_ai():
    """Test run_all_checks with AI enabled."""
    assert run_all_checks is not None, "run_all_checks must be defined"
    assert isinstance("echo", str), "command must be string"

    report = await run_all_checks("echo", ai=True)

    assert isinstance(report, AnalysisReport)
    assert report.command == "echo"
    assert len(report.checks) > 0


async def test_run_all_checks_without_ai():
    """Test run_all_checks without AI."""
    assert run_all_checks is not None, "run_all_checks must be defined"
    assert isinstance("echo", str), "command must be string"

    report = await run_all_checks("echo", ai=False)

    assert isinstance(report, AnalysisReport)
    assert report.command == "echo"
    assert len(report.checks) > 0


def test_run_all_checks_sync_wrapper():
    """Test run_all_checks in sync context."""
    assert run_all_checks is not None, "run_all_checks must be defined"
    assert isinstance("ls", str), "command must be string"

    report = asyncio.run(run_all_checks("ls"))

    assert isinstance(report, AnalysisReport)
    assert len(report.checks) > 0


async def test_run_all_checks_with_python():
    """Test run_all_checks with python command."""
    assert run_all_checks is not None, "run_all_checks must be defined"
    assert isinstance("python3", str), "command must be string"

    report = await run_all_checks("python3", ai=False)

    assert isinstance(report, AnalysisReport)
    assert report.command == "python3"
    assert len(report.checks) > 0
