"""
VibeGuard - Open-source AI security for vibe coders and AI companies.

Protect your LLM apps from prompt injection, PII leaks, secrets exposure,
and runaway costs with minimal code changes.

Basic usage:
    from vibeguard import Guard
    
    guard = Guard()
    result = guard.check_input(user_message)
    if result.blocked:
        print(f"Blocked: {result.reason}")

With integrations:
    from vibeguard.integrations.openai import GuardedOpenAI
    client = GuardedOpenAI()  # Drop-in replacement

Advanced features:
    from vibeguard.scanners.mcp import MCPScanner, scan_mcp_tools
    from vibeguard.scanners.toxicity import ToxicityScanner
    from vibeguard.scanners.hallucination import HallucinationScanner
    from vibeguard.authorization import ActionAuthorizer
    from vibeguard.dashboard import run_dashboard
"""

from vibeguard.guard import Guard
from vibeguard.models import (
    AuditLogEntry,
    CheckResult,
    Issue,
    IssueSeverity,
    IssueType,
    ScanDirection,
)
from vibeguard.scanners import Scanner
from vibeguard.policies.policy import Policy, Rule, Action

__version__ = "0.1.0"

__all__ = [
    # Core
    "Guard",
    "CheckResult",
    "Issue",
    "IssueSeverity",
    "IssueType",
    "ScanDirection",
    "AuditLogEntry",
    # Scanners
    "Scanner",
    # Policies
    "Policy",
    "Rule",
    "Action",
]

# Lazy imports for optional features
def __getattr__(name: str):
    """Lazy import for optional modules."""
    if name == "MCPScanner":
        from vibeguard.scanners.mcp import MCPScanner
        return MCPScanner
    elif name == "scan_mcp_tools":
        from vibeguard.scanners.mcp import scan_mcp_tools
        return scan_mcp_tools
    elif name == "ToxicityScanner":
        from vibeguard.scanners.toxicity import ToxicityScanner
        return ToxicityScanner
    elif name == "HallucinationScanner":
        from vibeguard.scanners.hallucination import HallucinationScanner
        return HallucinationScanner
    elif name == "ActionAuthorizer":
        from vibeguard.authorization import ActionAuthorizer
        return ActionAuthorizer
    elif name == "run_dashboard":
        from vibeguard.dashboard import run_dashboard
        return run_dashboard
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
