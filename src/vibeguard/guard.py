"""Main Guard class - the primary interface for VibeGuard."""

import logging
import time
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

    Recommended:
        # Enables PII + secrets redaction + injection sanitization
        guard = Guard(mode="privacy")
    """

    def __init__(
        self,
        # Mode preset (recommended way to configure behavior)
        mode: str = "standard",

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
        sanitize_on_injection: bool = False,  # NEW

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
        supported_modes = ("standard", "privacy", "strict", "monitor")
        if mode not in supported_modes:
            raise ValueError(f"Unknown mode: {mode}. Supported: {', '.join(supported_modes)}")

        # ---------------------------
        # Mode presets (highest priority)
        # ---------------------------
        if mode == "privacy":
            redact_pii = True
            redact_secrets = True
            block_on_injection = True
            # Prefer redaction over blocking on secrets in privacy mode
            block_on_secrets = False if block_on_secrets is True else block_on_secrets
            sanitize_on_injection = True
            policy = policy or Policy.strict()

        elif mode == "strict":
            redact_pii = True
            redact_secrets = True
            block_on_injection = True
            block_on_secrets = True
            sanitize_on_injection = True
            policy = policy or Policy.strict()

        elif mode == "monitor":
            # Detect and log, but do not block via legacy toggles
            block_on_injection = False
            block_on_secrets = False
            sanitize_on_injection = True
            policy = policy or Policy.strict()

        # "standard" leaves defaults as provided

        self.mode = mode
        self.redact_pii = redact_pii
        self.redact_secrets = redact_secrets
        self.block_on_injection = block_on_injection
        self.block_on_secrets = block_on_secrets
        self.sanitize_on_injection = sanitize_on_injection
        self.log_content = log_content
        self.audit_webhook = audit_webhook
        self.session_id = session_id

        # Initialize scanners
        self.scanners: list[Scanner] = []

        self._prompt_injection_scanner: PromptInjectionScanner | None = None
        if check_prompt_injection:
            self._prompt_injection_scanner = PromptInjectionScanner()
            self.scanners.append(self._prompt_injection_scanner)

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

        if extra_scanners:
            self.scanners.extend(extra_scanners)

        self._usage_tracker = UsageTracker(daily_limit=daily_token_limit) if daily_token_limit else None
        self.policy = policy or Policy.strict()

        self._audit_file: TextIO | None = None
        if audit_log:
            if isinstance(audit_log, (str, Path)):
                self._audit_file = open(audit_log, "a")
            else:
                self._audit_file = audit_log

    def check_input(self, text: str, metadata: dict[str, Any] | None = None) -> CheckResult:
        return self._check(text, ScanDirection.INPUT, metadata)

    def check_output(self, text: str, metadata: dict[str, Any] | None = None) -> CheckResult:
        return self._check(text, ScanDirection.OUTPUT, metadata)

    def _check(
        self,
        text: str,
        direction: ScanDirection,
        metadata: dict[str, Any] | None = None,
    ) -> CheckResult:
        start_time = time.time()
        issues: list[Issue] = []
        sanitized_text = text

        # Run scanners
        for scanner in self.scanners:
            if scanner.enabled:
                issues.extend(scanner.scan(text, direction))

        # Estimate tokens
        token_count = 0
        if self._token_scanner:
            token_count = self._token_scanner.estimate_tokens(text)

        # NEW: sanitize prompt injection content (useful in monitor/permissive flows and for logs)
        if self.sanitize_on_injection and self._prompt_injection_scanner:
            has_injection = any(
                i.type in (IssueType.PROMPT_INJECTION, IssueType.JAILBREAK)
                for i in issues
            )
            if has_injection:
                sanitized_text = self._prompt_injection_scanner.redact(sanitized_text)

        # Redact PII/secrets if enabled
        if self.redact_pii and self._pii_scanner:
            sanitized_text = self._pii_scanner.redact(sanitized_text)

        if self.redact_secrets and self._secrets_scanner:
            sanitized_text = self._secrets_scanner.redact(sanitized_text)

        result = CheckResult(
            original_text=text,
            sanitized_text=sanitized_text,
            issues=issues,
            token_count=token_count,
            scan_direction=direction,
            session_id=self.session_id,
            metadata=metadata or {},
        )

        # Policy evaluation
        action, message = self.policy.evaluate(result)

        if action == Action.BLOCK:
            result.blocked = True
            result.reason = message or self._generate_block_reason(result)

        elif action == Action.REDACT:
            # Only redact if flags are enabled (prevents surprising behavior)
            if self.sanitize_on_injection and self._prompt_injection_scanner:
                has_injection = any(
                    i.type in (IssueType.PROMPT_INJECTION, IssueType.JAILBREAK)
                    for i in result.issues
                )
                if has_injection:
                    result.sanitized_text = self._prompt_injection_scanner.redact(result.sanitized_text)

            if self.redact_pii and self._pii_scanner:
                result.sanitized_text = self._pii_scanner.redact(result.sanitized_text)

            if self.redact_secrets and self._secrets_scanner:
                result.sanitized_text = self._secrets_scanner.redact(result.sanitized_text)

        # Legacy blocking (if not already blocked)
        if not result.blocked:
            if self.block_on_injection:
                injection_issues = [
                    i for i in result.issues
                    if i.type in (IssueType.PROMPT_INJECTION, IssueType.JAILBREAK)
                    and i.severity in (IssueSeverity.HIGH, IssueSeverity.CRITICAL)
                ]
                if injection_issues:
                    result.blocked = True
                    result.reason = f"Prompt injection detected: {injection_issues[0].detail}"

            if self.block_on_secrets:
                secret_issues = [i for i in result.issues if i.type == IssueType.SECRET_DETECTED]
                if secret_issues:
                    result.blocked = True
                    result.reason = f"Secret detected: {secret_issues[0].detail}"

        # Usage limits
        if self._usage_tracker and not result.blocked:
            allowed, deny_reason = self._usage_tracker.check_limits(token_count)
            if not allowed:
                result.blocked = True
                result.reason = deny_reason
            else:
                self._usage_tracker.record_usage(token_count, self.session_id)

        latency_ms = (time.time() - start_time) * 1000
        self._log_audit(result, latency_ms)
        return result

    def _generate_block_reason(self, result: CheckResult) -> str:
        if not result.issues:
            return "Request blocked by policy"

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
                    "metadata": i.metadata,
                }
                for i in result.issues
            ],
            token_count=result.token_count,
            latency_ms=latency_ms,
        )

        if self.log_content:
            entry.original_text = result.original_text
            entry.sanitized_text = result.sanitized_text

        if self._audit_file:
            self._audit_file.write(entry.to_jsonl() + "\n")
            self._audit_file.flush()

        if self.audit_webhook:
            self._send_webhook(entry)

    def _send_webhook(self, entry: AuditLogEntry) -> None:
        try:
            import urllib.request

            data = entry.model_dump_json().encode("utf-8")
            req = urllib.request.Request(
                self.audit_webhook,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=1)
        except Exception as e:
            logger.warning(f"Failed to send audit webhook: {e}")

    def get_usage_stats(self) -> dict[str, Any]:
        if self._usage_tracker:
            return self._usage_tracker.get_usage_stats()
        return {}

    @classmethod
    def from_config(cls, config_path: str | Path) -> "Guard":
        with open(config_path) as f:
            config = yaml.safe_load(f)

        scanners_config = config.get("scanners", {})
        limits_config = config.get("limits", {})
        audit_config = config.get("audit", {})

        mode = config.get("mode")
        if not mode:
            pii_action = config.get("pii", {}).get("action")
            secrets_action = config.get("secrets", {}).get("action")
            if pii_action == "redact" or secrets_action == "redact":
                mode = "privacy"
            else:
                mode = "standard"

        return cls(
            mode=mode,
            check_prompt_injection=scanners_config.get("prompt_injection", True),
            check_pii=scanners_config.get("pii", True),
            check_secrets=scanners_config.get("secrets", True),
            check_tokens=scanners_config.get("tokens", True),
            redact_pii=config.get("pii", {}).get("action") == "redact",
            redact_secrets=config.get("secrets", {}).get("action") == "redact",
            block_on_injection=True,
            block_on_secrets=config.get("secrets", {}).get("action") == "block",
            max_input_tokens=limits_config.get("max_input_tokens"),
            max_output_tokens=limits_config.get("max_output_tokens"),
            daily_token_limit=limits_config.get("daily_token_limit"),
            audit_log=audit_config.get("destination") if audit_config.get("enabled") else None,
            log_content=audit_config.get("include_content", False),
        )

    def close(self) -> None:
        if self._audit_file:
            self._audit_file.close()
            self._audit_file = None

    def __enter__(self) -> "Guard":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
