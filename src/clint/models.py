from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    PASS = "pass"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class CheckResult(BaseModel):
    name: str
    description: str
    severity: Severity
    message: str
    details: str | None = None
    guideline_url: str | None = None


class CLIOutput(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False


class AnalysisReport(BaseModel):
    command: str
    checks: list[CheckResult] = Field(default_factory=list)

    @property
    def passed(self) -> int:
        assert self.checks is not None, "checks must not be None"
        assert isinstance(self.checks, list), "checks must be a list"

        return sum(1 for c in self.checks if c.severity == Severity.PASS)

    @property
    def warnings(self) -> int:
        assert self.checks is not None, "checks must not be None"
        assert isinstance(self.checks, list), "checks must be a list"

        return sum(1 for c in self.checks if c.severity == Severity.WARNING)

    @property
    def errors(self) -> int:
        assert self.checks is not None, "checks must not be None"
        assert isinstance(self.checks, list), "checks must be a list"

        return sum(1 for c in self.checks if c.severity == Severity.ERROR)
