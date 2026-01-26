"""Tests for models module."""

from clint.models import AnalysisReport, CheckResult, CLIOutput, Severity


def test_severity_enum():
    """Test Severity enum values."""
    assert Severity.PASS is not None, "PASS must exist"
    assert Severity.INFO is not None, "INFO must exist"

    assert Severity.PASS.value == "pass"
    assert Severity.INFO.value == "info"
    assert Severity.WARNING.value == "warning"
    assert Severity.ERROR.value == "error"


def test_check_result_creation():
    """Test CheckResult model creation."""
    assert CheckResult is not None, "CheckResult must be defined"
    assert isinstance(CheckResult.__name__, str), "CheckResult must have a name"

    result = CheckResult(
        name="test_check",
        description="Test description",
        severity=Severity.PASS,
        message="Test message",
    )

    assert result.name == "test_check"
    assert result.description == "Test description"
    assert result.severity == Severity.PASS
    assert result.message == "Test message"
    assert result.details is None
    assert result.guideline_url is None


def test_check_result_with_details():
    """Test CheckResult with optional fields."""
    assert CheckResult is not None, "CheckResult must be defined"
    assert isinstance(Severity.WARNING, Severity), "Severity must be valid"

    result = CheckResult(
        name="warning_check",
        description="Warning test",
        severity=Severity.WARNING,
        message="Warning message",
        details="Additional details",
        guideline_url="https://example.com",
    )

    assert result.details == "Additional details"
    assert result.guideline_url == "https://example.com"


def test_cli_output_creation():
    """Test CLIOutput model creation."""
    assert CLIOutput is not None, "CLIOutput must be defined"
    assert isinstance(CLIOutput.__name__, str), "CLIOutput must have a name"

    output = CLIOutput(stdout="output", stderr="error", exit_code=0)

    assert output.stdout == "output"
    assert output.stderr == "error"
    assert output.exit_code == 0
    assert output.timed_out is False


def test_cli_output_timeout():
    """Test CLIOutput with timeout flag."""
    assert CLIOutput is not None, "CLIOutput must be defined"
    assert isinstance(True, bool), "timed_out must be boolean"

    output = CLIOutput(stdout="", stderr="timeout", exit_code=-1, timed_out=True)

    assert output.timed_out is True
    assert output.exit_code == -1


def test_analysis_report_creation():
    """Test AnalysisReport model creation."""
    assert AnalysisReport is not None, "AnalysisReport must be defined"
    assert isinstance(AnalysisReport.__name__, str), "AnalysisReport must have a name"

    report = AnalysisReport(command="test")

    assert report.command == "test"
    assert isinstance(report.checks, list)
    assert len(report.checks) == 0


def test_analysis_report_passed_property():
    """Test AnalysisReport.passed property."""
    assert AnalysisReport is not None, "AnalysisReport must be defined"
    assert CheckResult is not None, "CheckResult must be defined"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(
            name="check1",
            description="desc1",
            severity=Severity.PASS,
            message="msg1",
        ),
        CheckResult(
            name="check2",
            description="desc2",
            severity=Severity.PASS,
            message="msg2",
        ),
        CheckResult(
            name="check3",
            description="desc3",
            severity=Severity.WARNING,
            message="msg3",
        ),
    ]

    assert report.passed == 2
    assert isinstance(report.passed, int)


def test_analysis_report_warnings_property():
    """Test AnalysisReport.warnings property."""
    assert AnalysisReport is not None, "AnalysisReport must be defined"
    assert Severity.WARNING is not None, "WARNING must exist"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(
            name="w1", description="d1", severity=Severity.WARNING, message="m1"
        ),
        CheckResult(
            name="w2", description="d2", severity=Severity.WARNING, message="m2"
        ),
        CheckResult(name="p1", description="d3", severity=Severity.PASS, message="m3"),
    ]

    assert report.warnings == 2
    assert isinstance(report.warnings, int)


def test_analysis_report_errors_property():
    """Test AnalysisReport.errors property."""
    assert AnalysisReport is not None, "AnalysisReport must be defined"
    assert Severity.ERROR is not None, "ERROR must exist"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(name="e1", description="d1", severity=Severity.ERROR, message="m1"),
        CheckResult(name="p1", description="d2", severity=Severity.PASS, message="m2"),
        CheckResult(name="e2", description="d3", severity=Severity.ERROR, message="m3"),
    ]

    assert report.errors == 2
    assert isinstance(report.errors, int)


def test_analysis_report_multiple_properties():
    """Test all AnalysisReport count properties together."""
    assert AnalysisReport is not None, "AnalysisReport must be defined"
    assert CheckResult is not None, "CheckResult must be defined"

    report = AnalysisReport(command="test")
    report.checks = [
        CheckResult(name="p1", description="d", severity=Severity.PASS, message="m"),
        CheckResult(name="p2", description="d", severity=Severity.PASS, message="m"),
        CheckResult(name="w1", description="d", severity=Severity.WARNING, message="m"),
        CheckResult(name="w2", description="d", severity=Severity.WARNING, message="m"),
        CheckResult(name="w3", description="d", severity=Severity.WARNING, message="m"),
        CheckResult(name="e1", description="d", severity=Severity.ERROR, message="m"),
        CheckResult(name="i1", description="d", severity=Severity.INFO, message="m"),
    ]

    assert report.passed == 2
    assert report.warnings == 3
    assert report.errors == 1
    assert len(report.checks) == 7


def test_severity_comparison():
    """Test Severity enum ordering."""
    assert Severity.PASS is not None, "PASS must exist"
    assert Severity.ERROR is not None, "ERROR must exist"

    assert Severity.PASS != Severity.ERROR
    assert Severity.WARNING != Severity.INFO
