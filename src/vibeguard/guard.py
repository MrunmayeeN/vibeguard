"""Main Guard class - the primary interface for VibeGuard."""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

import yaml

from vibeguard.models import (
    AuditLogEntry,
    CheckResult,
    Issue,
    IssueType,
    IssueSeverity,
    ScanDirection,
)
from vibeguard.policies.policy import Action, Policy
from vibeguard.scanners import Scanner
from vibeguard.scanners.pii import PIIScanner
from vibeguard.scanners.prompt_injection import PromptInjectionScanner
from vibeguard.scanners.secrets import SecretsScanner
from vibeguard.scanners.tokens import TokenScanner, UsageTracker

logger = logging.getLogger("vibeguard")


class Guard:
    """
    Main security guard for LLM applications.
    
    The Guard scans inputs and outputs for security issues including:
    - Prompt injection attempts
    - PII (personally identifiable information)
    - Leaked secrets and API keys
    - Token limit violations
    
    Basic usage:
        guard = Guard()
        result = guard.check_input(user_message)
        if result.blocked:
            print(f"Blocked: {result.reason}")
        else:
            # Safe to send to LLM
            response = llm.generate(result.sanitized_text)
            output_result = guard.check_output(response)
    
    With configuration:
        guard = Guard(
            redact_pii=True,
            max_input_tokens=4000,
            audit_log="./audit.jsonl"
        )
    """
    
    def __init__(
        self,
        # Scanner toggles
        check_prompt_injection: bool = True,
        check_pii: bool = True,
        check_secrets: bool = True,
        check_tokens: bool = True,
        
        # Behavior options
        redact_pii: bool = False,
        redact_secrets: bool = False,
        block_on_injection: bool = True,
        block_on_secrets: bool = True,
        
        # Token limits
        max_input_tokens: int | None = None,
        max_output_tokens: int | None = None,
        daily_token_limit: int | None = None,
        
        # Policy
        policy: Policy | None = None,
        
        # Logging
        audit_log: str | Path | TextIO | None = None,
        log_content: bool = False,  # Whether to log actual content
        audit_webhook: str | None = None,
        
        # Custom scanners
        extra_scanners: list[Scanner] | None = None,
        
        # Session tracking
        session_id: str | None = None,
    ):
        """
        Initialize the Guard.
        
        Args:
            check_prompt_injection: Enable prompt injection detection
            check_pii: Enable PII detection
            check_secrets: Enable secrets detection
            check_tokens: Enable token counting
            redact_pii: Automatically redact detected PII
            redact_secrets: Automatically redact detected secrets
            block_on_injection: Block requests with prompt injection
            block_on_secrets: Block requests with detected secrets
            max_input_tokens: Maximum tokens for input
            max_output_tokens: Maximum tokens for output
            daily_token_limit: Maximum tokens per day
            policy: Custom policy for rule evaluation
            audit_log: Path to audit log file or file-like object
            log_content: Whether to include content in audit logs
            audit_webhook: URL to send audit events via POST
            extra_scanners: Additional custom scanners
            session_id: Session identifier for tracking
        """
        self.redact_pii = redact_pii
        self.redact_secrets = redact_secrets
        self.block_on_injection = block_on_injection
        self.block_on_secrets = block_on_secrets
        self.log_content = log_content
        self.audit_webhook = audit_webhook
        self.session_id = session_id
        
        # Initialize scanners
        self.scanners: list[Scanner] = []
        
        if check_prompt_injection:
            self.scanners.append(PromptInjectionScanner())
        
        if check_pii:
            self._pii_scanner = PIIScanner()
            self.scanners.append(self._pii_scanner)
        else:
            self._pii_scanner = None
        
        if check_secrets:
            self._secrets_scanner = SecretsScanner()
            self.scanners.append(self._secrets_scanner)
        else:
            self._secrets_scanner = None
        
        if check_tokens:
            self._token_scanner = TokenScanner(
                max_input_tokens=max_input_tokens,
                max_output_tokens=max_output_tokens,
            )
            self.scanners.append(self._token_scanner)
        else:
            self._token_scanner = None
        
        # Add custom scanners
        if extra_scanners:
            self.scanners.extend(extra_scanners)
        
        # Usage tracking
        self._usage_tracker = UsageTracker(
            daily_limit=daily_token_limit,
        ) if daily_token_limit else None
        
        # Policy
        self.policy = policy or Policy.strict()
        
        # Audit logging
        self._audit_file: TextIO | None = None
        if audit_log:
            if isinstance(audit_log, (str, Path)):
                self._audit_file = open(audit_log, "a")
            else:
                self._audit_file = audit_log
    
    def check_input(self, text: str, metadata: dict[str, Any] | None = None) -> CheckResult:
        """
        Check input text before sending to LLM.
        
        Args:
            text: The input text to check
            metadata: Optional metadata to include in result
            
        Returns:
            CheckResult with issues and sanitized text
        """
        return self._check(text, ScanDirection.INPUT, metadata)
    
    def check_output(self, text: str, metadata: dict[str, Any] | None = None) -> CheckResult:
        """
        Check output text from LLM before showing to user.
        
        Args:
            text: The output text to check
            metadata: Optional metadata to include in result
            
        Returns:
            CheckResult with issues and sanitized text
        """
        return self._check(text, ScanDirection.OUTPUT, metadata)
    
    def _check(
        self, 
        text: str, 
        direction: ScanDirection,
        metadata: dict[str, Any] | None = None,
    ) -> CheckResult:
        """
        Internal method to check text.
        
        Args:
            text: Text to check
            direction: Input or output
            metadata: Optional metadata
            
        Returns:
            CheckResult
        """
        start_time = time.time()
        issues: list[Issue] = []
        sanitized_text = text
        
        # Run all scanners
        for scanner in self.scanners:
            if scanner.enabled:
                scanner_issues = scanner.scan(text, direction)
                issues.extend(scanner_issues)
        
        # Estimate tokens
        token_count = 0
        if self._token_scanner:
            token_count = self._token_scanner.estimate_tokens(text)
        
        # Apply redaction if enabled
        if self.redact_pii and self._pii_scanner:
            sanitized_text = self._pii_scanner.redact(sanitized_text)
        
        if self.redact_secrets and self._secrets_scanner:
            sanitized_text = self._secrets_scanner.redact(sanitized_text)
        
        # Create initial result
        result = CheckResult(
            original_text=text,
            sanitized_text=sanitized_text,
            issues=issues,
            token_count=token_count,
            scan_direction=direction,
            session_id=self.session_id,
            metadata=metadata or {},
        )
        
        # Evaluate policy
        action, message = self.policy.evaluate(result)
        
        # Apply action
        if action == Action.BLOCK:
            result.blocked = True
            result.reason = message or self._generate_block_reason(result)
        elif action == Action.REDACT:
            # Ensure redaction is applied
            if self._pii_scanner:
                result.sanitized_text = self._pii_scanner.redact(result.sanitized_text)
            if self._secrets_scanner:
                result.sanitized_text = self._secrets_scanner.redact(result.sanitized_text)
        
        # Legacy blocking behavior (if no policy or policy allows)
        if not result.blocked:
            if self.block_on_injection:
                injection_issues = [i for i in issues if i.type in (
                    IssueType.PROMPT_INJECTION, 
                    IssueType.JAILBREAK
                ) and i.severity in (IssueSeverity.HIGH, IssueSeverity.CRITICAL)]
                if injection_issues:
                    result.blocked = True
                    result.reason = f"Prompt injection detected: {injection_issues[0].detail}"
            
            if self.block_on_secrets:
                secret_issues = [i for i in issues if i.type == IssueType.SECRET_DETECTED]
                if secret_issues:
                    result.blocked = True
                    result.reason = f"Secret detected: {secret_issues[0].detail}"
        
        # Track usage
        if self._usage_tracker and not result.blocked:
            allowed, deny_reason = self._usage_tracker.check_limits(token_count)
            if not allowed:
                result.blocked = True
                result.reason = deny_reason
            else:
                self._usage_tracker.record_usage(token_count, self.session_id)
        
        # Calculate latency
        latency_ms = (time.time() - start_time) * 1000
        
        # Audit logging
        self._log_audit(result, latency_ms)
        
        return result
    
    def _generate_block_reason(self, result: CheckResult) -> str:
        """Generate a human-readable block reason from issues."""
        if not result.issues:
            return "Request blocked by policy"
        
        # Group by type
        by_type: dict[IssueType, list[Issue]] = {}
        for issue in result.issues:
            by_type.setdefault(issue.type, []).append(issue)
        
        parts = []
        for issue_type, type_issues in by_type.items():
            if len(type_issues) == 1:
                parts.append(type_issues[0].detail)
            else:
                parts.append(f"{len(type_issues)} {issue_type.value} issues")
        
        return "; ".join(parts)
    
    def _log_audit(self, result: CheckResult, latency_ms: float) -> None:
        """Log an audit entry."""
        entry = AuditLogEntry(
            session_id=self.session_id,
            direction=result.scan_direction,
            blocked=result.blocked,
            issues=[
                {
                    "type": i.type.value,
                    "severity": i.severity.value,
                    "detail": i.detail,
                    "scanner": i.scanner,
                }
                for i in result.issues
            ],
            token_count=result.token_count,
            latency_ms=latency_ms,
        )
        
        if self.log_content:
            entry.original_text = result.original_text
            entry.sanitized_text = result.sanitized_text
        
        # Write to file
        if self._audit_file:
            self._audit_file.write(entry.to_jsonl() + "\n")
            self._audit_file.flush()
        
        # Send to webhook
        if self.audit_webhook:
            self._send_webhook(entry)
    
    def _send_webhook(self, entry: AuditLogEntry) -> None:
        """Send audit entry to webhook (non-blocking)."""
        try:
            import urllib.request
            
            data = entry.model_dump_json().encode("utf-8")
            req = urllib.request.Request(
                self.audit_webhook,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # Fire and forget (with short timeout)
            urllib.request.urlopen(req, timeout=1)
        except Exception as e:
            logger.warning(f"Failed to send audit webhook: {e}")
    
    def get_usage_stats(self) -> dict[str, Any]:
        """Get current usage statistics."""
        if self._usage_tracker:
            return self._usage_tracker.get_usage_stats()
        return {}
    
    @classmethod
    def from_config(cls, config_path: str | Path) -> "Guard":
        """
        Create a Guard from a YAML configuration file.
        
        Args:
            config_path: Path to YAML config file
            
        Returns:
            Configured Guard instance
        """
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        # Extract scanner config
        scanners_config = config.get("scanners", {})
        
        # Extract limits
        limits_config = config.get("limits", {})
        
        # Extract audit config
        audit_config = config.get("audit", {})
        
        return cls(
            check_prompt_injection=scanners_config.get("prompt_injection", True),
            check_pii=scanners_config.get("pii", True),
            check_secrets=scanners_config.get("secrets", True),
            check_tokens=scanners_config.get("tokens", True),
            redact_pii=config.get("pii", {}).get("action") == "redact",
            redact_secrets=config.get("secrets", {}).get("action") == "redact",
            block_on_injection=True,  # Always block injection by default
            block_on_secrets=config.get("secrets", {}).get("action") == "block",
            max_input_tokens=limits_config.get("max_input_tokens"),
            max_output_tokens=limits_config.get("max_output_tokens"),
            daily_token_limit=limits_config.get("daily_token_limit"),
            audit_log=audit_config.get("destination") if audit_config.get("enabled") else None,
            log_content=audit_config.get("include_content", False),
        )
    
    def close(self) -> None:
        """Close resources (audit file, etc.)."""
        if self._audit_file:
            self._audit_file.close()
            self._audit_file = None
    
    def __enter__(self) -> "Guard":
        return self
    
    def __exit__(self, *args: Any) -> None:
        self.close()
