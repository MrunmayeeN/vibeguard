"""Secrets detection scanner for API keys, passwords, and sensitive credentials."""

import re
from enum import Enum
from typing import ClassVar

from vibeguard.models import Issue, IssueSeverity, IssueType, ScanDirection
from vibeguard.scanners import Scanner


class SecretType(str, Enum):
    """Types of secrets that can be detected."""
    
    OPENAI_KEY = "openai_key"
    ANTHROPIC_KEY = "anthropic_key"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GCP_KEY = "gcp_key"
    AZURE_KEY = "azure_key"
    GITHUB_TOKEN = "github_token"
    GITHUB_PAT = "github_pat"
    SLACK_TOKEN = "slack_token"
    STRIPE_KEY = "stripe_key"
    TWILIO_KEY = "twilio_key"
    SENDGRID_KEY = "sendgrid_key"
    DATABASE_URL = "database_url"
    PRIVATE_KEY = "private_key"
    JWT_TOKEN = "jwt_token"
    GENERIC_API_KEY = "generic_api_key"
    GENERIC_SECRET = "generic_secret"
    PASSWORD = "password"


class SecretsScanner(Scanner):
    """
    Detects accidentally leaked secrets, API keys, and credentials.
    
    Supports detection of:
    - OpenAI API keys
    - Anthropic API keys  
    - AWS credentials
    - GCP/Azure keys
    - GitHub tokens
    - Database connection strings
    - Private keys (RSA, etc.)
    - JWT tokens
    - Generic API keys and passwords
    """
    
    name: str = "secrets"
    
    # Secret patterns with their types and descriptions
    PATTERNS: ClassVar[list[tuple[SecretType, str, str, IssueSeverity]]] = [
        # OpenAI
        (
            SecretType.OPENAI_KEY,
            r"sk-(?:proj-)?[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}",
            "OpenAI API key",
            IssueSeverity.CRITICAL,
        ),
        (
            SecretType.OPENAI_KEY,
            r"sk-[A-Za-z0-9_-]{48,}",
            "OpenAI API key (new format)",
            IssueSeverity.CRITICAL,
        ),
        
        # Anthropic
        (
            SecretType.ANTHROPIC_KEY,
            r"sk-ant-[A-Za-z0-9_-]{90,}",
            "Anthropic API key",
            IssueSeverity.CRITICAL,
        ),
        
        # AWS
        (
            SecretType.AWS_ACCESS_KEY,
            r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "AWS Access Key ID",
            IssueSeverity.CRITICAL,
        ),
        (
            SecretType.AWS_SECRET_KEY,
            r"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
            "AWS Secret Access Key",
            IssueSeverity.CRITICAL,
        ),
        
        # GCP
        (
            SecretType.GCP_KEY,
            r"AIza[0-9A-Za-z_-]{35}",
            "Google Cloud API key",
            IssueSeverity.CRITICAL,
        ),
        (
            SecretType.GCP_KEY,
            r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
            "Google OAuth client ID",
            IssueSeverity.HIGH,
        ),
        
        # Azure
        (
            SecretType.AZURE_KEY,
            r"(?i)(?:azure|microsoft)[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{32,})",
            "Azure API key",
            IssueSeverity.CRITICAL,
        ),
        
        # GitHub
        (
            SecretType.GITHUB_TOKEN,
            r"ghp_[A-Za-z0-9]{36,}",
            "GitHub Personal Access Token",
            IssueSeverity.CRITICAL,
        ),
        (
            SecretType.GITHUB_TOKEN,
            r"gho_[A-Za-z0-9]{36,}",
            "GitHub OAuth Access Token",
            IssueSeverity.CRITICAL,
        ),
        (
            SecretType.GITHUB_TOKEN,
            r"ghu_[A-Za-z0-9]{36,}",
            "GitHub User-to-Server Token",
            IssueSeverity.CRITICAL,
        ),
        (
            SecretType.GITHUB_TOKEN,
            r"ghs_[A-Za-z0-9]{36,}",
            "GitHub Server-to-Server Token",
            IssueSeverity.CRITICAL,
        ),
        (
            SecretType.GITHUB_PAT,
            r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
            "GitHub Fine-grained PAT",
            IssueSeverity.CRITICAL,
        ),
        
        # Slack
        (
            SecretType.SLACK_TOKEN,
            r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
            "Slack token",
            IssueSeverity.CRITICAL,
        ),
        
        # Stripe
        (
            SecretType.STRIPE_KEY,
            r"sk_live_[A-Za-z0-9]{24,}",
            "Stripe live secret key",
            IssueSeverity.CRITICAL,
        ),
        (
            SecretType.STRIPE_KEY,
            r"sk_test_[A-Za-z0-9]{24,}",
            "Stripe test secret key",
            IssueSeverity.HIGH,
        ),
        (
            SecretType.STRIPE_KEY,
            r"rk_live_[A-Za-z0-9]{24,}",
            "Stripe restricted key",
            IssueSeverity.CRITICAL,
        ),
        
        # Twilio
        (
            SecretType.TWILIO_KEY,
            r"SK[A-Za-z0-9]{32}",
            "Twilio API key",
            IssueSeverity.HIGH,
        ),
        
        # SendGrid
        (
            SecretType.SENDGRID_KEY,
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            "SendGrid API key",
            IssueSeverity.HIGH,
        ),
        
        # Database URLs
        (
            SecretType.DATABASE_URL,
            r"(?i)(?:postgres|mysql|mongodb|redis)(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
            "Database connection string with credentials",
            IssueSeverity.CRITICAL,
        ),
        
        # Private keys
        (
            SecretType.PRIVATE_KEY,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "Private key header detected",
            IssueSeverity.CRITICAL,
        ),
        (
            SecretType.PRIVATE_KEY,
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "PGP private key detected",
            IssueSeverity.CRITICAL,
        ),
        
        # JWT tokens
        (
            SecretType.JWT_TOKEN,
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "JWT token detected",
            IssueSeverity.HIGH,
        ),
        
        # Generic patterns (lower confidence)
        (
            SecretType.GENERIC_API_KEY,
            r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})",
            "Generic API key pattern",
            IssueSeverity.MEDIUM,
        ),
        (
            SecretType.GENERIC_SECRET,
            r"(?i)(?:secret|token|auth)[_-]?(?:key)?['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{16,})",
            "Generic secret pattern",
            IssueSeverity.MEDIUM,
        ),
        (
            SecretType.PASSWORD,
            r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})",
            "Password in plaintext",
            IssueSeverity.HIGH,
        ),
    ]
    
    def __init__(
        self,
        detect_types: list[SecretType] | None = None,
        exclude_types: list[SecretType] | None = None,
        check_generic: bool = True,
    ):
        """
        Initialize the secrets scanner.
        
        Args:
            detect_types: Specific secret types to detect (default: all)
            exclude_types: Secret types to exclude from detection
            check_generic: Whether to check for generic API key/secret patterns
        """
        self.detect_types = detect_types
        self.exclude_types = exclude_types or []
        self.check_generic = check_generic
        
        self._compiled_patterns: list[tuple[SecretType, re.Pattern, str, IssueSeverity]] = []
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for enabled secret types."""
        self._compiled_patterns = []
        
        generic_types = {
            SecretType.GENERIC_API_KEY,
            SecretType.GENERIC_SECRET,
            SecretType.PASSWORD,
        }
        
        for secret_type, pattern, detail, severity in self.PATTERNS:
            # Skip excluded types
            if secret_type in self.exclude_types:
                continue
            
            # Skip generic patterns if disabled
            if not self.check_generic and secret_type in generic_types:
                continue
            
            # If specific types requested, only include those
            if self.detect_types and secret_type not in self.detect_types:
                continue
            
            self._compiled_patterns.append((
                secret_type,
                re.compile(pattern),
                detail,
                severity,
            ))
    
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        """
        Scan text for secrets.
        
        Args:
            text: The text to scan
            direction: Input or output direction
            
        Returns:
            List of detected secret issues
        """
        issues: list[Issue] = []
        seen_positions: set[tuple[int, int]] = set()  # Avoid duplicate detections
        
        for secret_type, compiled_pattern, detail, severity in self._compiled_patterns:
            matches = list(compiled_pattern.finditer(text))
            
            for match in matches:
                pos = (match.start(), match.end())
                
                # Skip if we've already flagged this position
                if self._overlaps_seen(pos, seen_positions):
                    continue
                
                seen_positions.add(pos)
                matched_text = match.group()
                
                issues.append(Issue(
                    type=IssueType.SECRET_DETECTED,
                    severity=severity,
                    detail=detail,
                    span=pos,
                    scanner=self.name,
                    metadata={
                        "secret_type": secret_type.value,
                        "redacted_preview": self._redact_secret(matched_text),
                    },
                ))
        
        return issues
    
    def _overlaps_seen(
        self, 
        pos: tuple[int, int], 
        seen: set[tuple[int, int]]
    ) -> bool:
        """Check if position overlaps with any seen position."""
        start, end = pos
        for seen_start, seen_end in seen:
            # Check for overlap
            if start < seen_end and end > seen_start:
                return True
        return False
    
    def _redact_secret(self, secret: str) -> str:
        """Partially redact a secret for logging."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
    
    def redact(self, text: str) -> str:
        """
        Redact all detected secrets from text.
        
        Args:
            text: The text to redact
            
        Returns:
            Text with secrets replaced by [REDACTED]
        """
        result = text
        
        # Collect all matches
        all_matches: list[tuple[int, int, SecretType]] = []
        
        for secret_type, compiled_pattern, _, _ in self._compiled_patterns:
            for match in compiled_pattern.finditer(text):
                all_matches.append((match.start(), match.end(), secret_type))
        
        # Sort by position (descending) to replace from end to start
        all_matches.sort(key=lambda x: x[0], reverse=True)
        
        # Replace matches
        for start, end, secret_type in all_matches:
            result = result[:start] + f"[{secret_type.value.upper()}_REDACTED]" + result[end:]
        
        return result
