"""Core data models for VibeGuard."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IssueType(str, Enum):
    """Types of security issues that can be detected."""
    
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_DETECTED = "pii_detected"
    SECRET_DETECTED = "secret_detected"
    TOXIC_CONTENT = "toxic_content"
    TOKEN_LIMIT_EXCEEDED = "token_limit_exceeded"
    CUSTOM_RULE = "custom_rule"
    MCP_TOOL_POISONING = "mcp_tool_poisoning"


class IssueSeverity(str, Enum):
    """Severity levels for detected issues."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanDirection(str, Enum):
    """Direction of the scan (input to LLM or output from LLM)."""
    
    INPUT = "input"
    OUTPUT = "output"


class Issue(BaseModel):
    """A detected security issue."""
    
    type: IssueType
    severity: IssueSeverity
    detail: str
    span: tuple[int, int] | None = None  # Start and end position in text
    scanner: str = "unknown"  # Which scanner detected this
    metadata: dict[str, Any] = Field(default_factory=dict)
    
    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.type.value}: {self.detail}"


class CheckResult(BaseModel):
    """Result of checking input or output text."""
    
    original_text: str
    sanitized_text: str
    blocked: bool = False
    reason: str | None = None
    issues: list[Issue] = Field(default_factory=list)
    token_count: int = 0
    scan_direction: ScanDirection = ScanDirection.INPUT
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    
    @property
    def has_issues(self) -> bool:
        """Check if any issues were detected."""
        return len(self.issues) > 0
    
    @property
    def highest_severity(self) -> IssueSeverity | None:
        """Get the highest severity among all issues."""
        if not self.issues:
            return None
        severity_order = [
            IssueSeverity.LOW,
            IssueSeverity.MEDIUM, 
            IssueSeverity.HIGH,
            IssueSeverity.CRITICAL,
        ]
        max_severity = IssueSeverity.LOW
        for issue in self.issues:
            if severity_order.index(issue.severity) > severity_order.index(max_severity):
                max_severity = issue.severity
        return max_severity
    
    def get_issues_by_type(self, issue_type: IssueType) -> list[Issue]:
        """Get all issues of a specific type."""
        return [i for i in self.issues if i.type == issue_type]
    
    def get_issues_by_severity(self, severity: IssueSeverity) -> list[Issue]:
        """Get all issues of a specific severity."""
        return [i for i in self.issues if i.severity == severity]


class AuditLogEntry(BaseModel):
    """Entry for audit logging."""
    
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    session_id: str | None = None
    direction: ScanDirection
    blocked: bool
    issues: list[dict[str, Any]] = Field(default_factory=list)
    token_count: int = 0
    latency_ms: float = 0.0
    # Content fields - optionally included based on config
    original_text: str | None = None
    sanitized_text: str | None = None
    
    def to_jsonl(self) -> str:
        """Convert to JSON Lines format."""
        return self.model_dump_json()
