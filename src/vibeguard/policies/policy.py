"""Policy engine for defining and enforcing security rules."""

from enum import Enum
from typing import Any, Callable

from pydantic import BaseModel, Field

from vibeguard.models import CheckResult, Issue, IssueSeverity, IssueType


class Action(str, Enum):
    """Actions to take when a rule matches."""
    
    ALLOW = "allow"  # Allow the request to proceed
    WARN = "warn"  # Log warning but allow
    BLOCK = "block"  # Block the request
    REDACT = "redact"  # Redact sensitive content and allow
    REQUIRE_APPROVAL = "require_approval"  # Pause for human approval


class Rule(BaseModel):
    """
    A policy rule that defines conditions and actions.
    
    Rules are evaluated in order. The first matching rule determines
    the action taken.
    """
    
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 0  # Higher priority rules are evaluated first
    
    # Conditions (any match triggers the rule)
    issue_types: list[IssueType] | None = None
    min_severity: IssueSeverity | None = None
    max_severity: IssueSeverity | None = None
    scanner_names: list[str] | None = None
    
    # Custom condition function (takes CheckResult, returns bool)
    # Note: This can't be serialized to YAML, use for programmatic rules only
    condition: Callable[[CheckResult], bool] | None = Field(default=None, exclude=True)
    
    # Action to take
    action: Action = Action.BLOCK
    message: str | None = None  # Custom message for the user
    
    class Config:
        arbitrary_types_allowed = True
    
    def matches(self, result: CheckResult) -> bool:
        """
        Check if this rule matches the given result.
        
        Args:
            result: The check result to evaluate
            
        Returns:
            True if the rule matches
        """
        if not self.enabled:
            return False
        
        # If custom condition is provided, use it
        if self.condition is not None:
            return self.condition(result)
        
        # If no conditions are set, rule doesn't match
        if not any([
            self.issue_types,
            self.min_severity,
            self.max_severity,
            self.scanner_names,
        ]):
            return False
        
        # Check each issue against conditions
        for issue in result.issues:
            if self._issue_matches(issue):
                return True
        
        return False
    
    def _issue_matches(self, issue: Issue) -> bool:
        """Check if an individual issue matches the rule conditions."""
        severity_order = [
            IssueSeverity.LOW,
            IssueSeverity.MEDIUM,
            IssueSeverity.HIGH,
            IssueSeverity.CRITICAL,
        ]
        
        # Check issue type
        if self.issue_types and issue.type not in self.issue_types:
            return False
        
        # Check minimum severity
        if self.min_severity:
            if severity_order.index(issue.severity) < severity_order.index(self.min_severity):
                return False
        
        # Check maximum severity
        if self.max_severity:
            if severity_order.index(issue.severity) > severity_order.index(self.max_severity):
                return False
        
        # Check scanner name
        if self.scanner_names and issue.scanner not in self.scanner_names:
            return False
        
        return True


class Policy(BaseModel):
    """
    A collection of rules that define security policy.
    
    Example:
        policy = Policy(
            name="production",
            rules=[
                Rule(
                    name="block_critical",
                    min_severity=IssueSeverity.CRITICAL,
                    action=Action.BLOCK,
                ),
                Rule(
                    name="warn_medium",
                    min_severity=IssueSeverity.MEDIUM,
                    max_severity=IssueSeverity.HIGH,
                    action=Action.WARN,
                ),
            ]
        )
    """
    
    name: str = "default"
    description: str = ""
    rules: list[Rule] = Field(default_factory=list)
    
    # Default actions when no rule matches
    default_action: Action = Action.ALLOW
    default_action_on_issues: Action = Action.WARN
    
    class Config:
        arbitrary_types_allowed = True
    
    def evaluate(self, result: CheckResult) -> tuple[Action, str | None]:
        """
        Evaluate the policy against a check result.
        
        Args:
            result: The check result to evaluate
            
        Returns:
            Tuple of (action, message)
        """
        # Sort rules by priority (higher first)
        sorted_rules = sorted(self.rules, key=lambda r: r.priority, reverse=True)
        
        # Find first matching rule
        for rule in sorted_rules:
            if rule.matches(result):
                return rule.action, rule.message
        
        # No rule matched - use defaults
        if result.has_issues:
            return self.default_action_on_issues, None
        
        return self.default_action, None
    
    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the policy."""
        self.rules.append(rule)
    
    def remove_rule(self, name: str) -> bool:
        """Remove a rule by name. Returns True if found and removed."""
        for i, rule in enumerate(self.rules):
            if rule.name == name:
                self.rules.pop(i)
                return True
        return False
    
    @classmethod
    def strict(cls) -> "Policy":
        """
        Create a strict policy that blocks on any high+ severity issue.
        
        Suitable for production environments with sensitive data.
        """
        return cls(
            name="strict",
            description="Strict policy - blocks high+ severity issues",
            rules=[
                Rule(
                    name="block_critical",
                    description="Block all critical severity issues",
                    min_severity=IssueSeverity.CRITICAL,
                    action=Action.BLOCK,
                    priority=100,
                ),
                Rule(
                    name="block_high",
                    description="Block all high severity issues",
                    min_severity=IssueSeverity.HIGH,
                    max_severity=IssueSeverity.HIGH,
                    action=Action.BLOCK,
                    priority=90,
                ),
                Rule(
                    name="warn_medium",
                    description="Warn on medium severity issues",
                    min_severity=IssueSeverity.MEDIUM,
                    max_severity=IssueSeverity.MEDIUM,
                    action=Action.WARN,
                    priority=50,
                ),
            ],
            default_action_on_issues=Action.WARN,
        )
    
    @classmethod
    def permissive(cls) -> "Policy":
        """
        Create a permissive policy that only blocks critical issues.
        
        Suitable for development and testing.
        """
        return cls(
            name="permissive",
            description="Permissive policy - only blocks critical issues",
            rules=[
                Rule(
                    name="block_critical",
                    description="Block only critical severity issues",
                    min_severity=IssueSeverity.CRITICAL,
                    action=Action.BLOCK,
                    priority=100,
                ),
                Rule(
                    name="warn_secrets",
                    description="Warn on any detected secrets",
                    issue_types=[IssueType.SECRET_DETECTED],
                    action=Action.WARN,
                    priority=80,
                ),
            ],
            default_action_on_issues=Action.ALLOW,
        )
    
    @classmethod
    def redact_pii(cls) -> "Policy":
        """
        Create a policy that redacts PII but allows other issues through.
        """
        return cls(
            name="redact_pii",
            description="Redact PII, block secrets, warn on other issues",
            rules=[
                Rule(
                    name="redact_pii",
                    description="Redact all detected PII",
                    issue_types=[IssueType.PII_DETECTED],
                    action=Action.REDACT,
                    priority=100,
                ),
                Rule(
                    name="block_secrets",
                    description="Block all detected secrets",
                    issue_types=[IssueType.SECRET_DETECTED],
                    action=Action.BLOCK,
                    priority=90,
                ),
                Rule(
                    name="block_injection",
                    description="Block prompt injection attempts",
                    issue_types=[IssueType.PROMPT_INJECTION, IssueType.JAILBREAK],
                    min_severity=IssueSeverity.HIGH,
                    action=Action.BLOCK,
                    priority=80,
                ),
            ],
            default_action_on_issues=Action.WARN,
        )
