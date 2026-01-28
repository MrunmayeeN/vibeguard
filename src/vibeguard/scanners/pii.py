"""PII (Personally Identifiable Information) detection scanner."""

import re
from enum import Enum
from typing import ClassVar

from vibeguard.models import Issue, IssueSeverity, IssueType, ScanDirection
from vibeguard.scanners import Scanner


class PIIType(str, Enum):
    """Types of PII that can be detected."""
    
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    DATE_OF_BIRTH = "date_of_birth"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    ADDRESS = "address"


class PIIScanner(Scanner):
    """
    Detects Personally Identifiable Information (PII).
    
    Supports detection of:
    - Email addresses
    - Phone numbers (US, international)
    - Social Security Numbers
    - Credit card numbers (with Luhn validation)
    - IP addresses (IPv4 and IPv6)
    - Dates of birth
    - And more via custom patterns
    """
    
    name: str = "pii"
    
    # PII detection patterns
    PATTERNS: ClassVar[dict[PIIType, tuple[str, str]]] = {
        PIIType.EMAIL: (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "Email address detected",
        ),
        PIIType.PHONE: (
            # Matches various phone formats
            r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
            r"|\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}",
            "Phone number detected",
        ),
        PIIType.SSN: (
            r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
            "Social Security Number detected",
        ),
        PIIType.CREDIT_CARD: (
            # Major card formats (Visa, MC, Amex, Discover)
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?"  # Visa
            r"|5[1-5][0-9]{14}"  # Mastercard
            r"|3[47][0-9]{13}"  # Amex
            r"|6(?:011|5[0-9]{2})[0-9]{12}"  # Discover
            r"|(?:\d{4}[-\s]?){3}\d{4})\b",  # Any card with separators
            "Credit card number detected",
        ),
        PIIType.IP_ADDRESS: (
            # IPv4
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            # IPv6 (simplified)
            r"|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
            "IP address detected",
        ),
        PIIType.DATE_OF_BIRTH: (
            # Common date formats that might be DOB
            r"\b(?:DOB|Date\s+of\s+Birth|Born)[:\s]*"
            r"(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})",
            "Date of birth detected",
        ),
    }
    
    # Redaction placeholders
    REDACTION_PLACEHOLDERS: ClassVar[dict[PIIType, str]] = {
        PIIType.EMAIL: "[EMAIL]",
        PIIType.PHONE: "[PHONE]",
        PIIType.SSN: "[SSN]",
        PIIType.CREDIT_CARD: "[CREDIT_CARD]",
        PIIType.IP_ADDRESS: "[IP_ADDRESS]",
        PIIType.DATE_OF_BIRTH: "[DOB]",
        PIIType.PASSPORT: "[PASSPORT]",
        PIIType.DRIVERS_LICENSE: "[DRIVERS_LICENSE]",
        PIIType.ADDRESS: "[ADDRESS]",
    }
    
    def __init__(
        self,
        detect_types: list[PIIType] | None = None,
        severity: IssueSeverity = IssueSeverity.MEDIUM,
        custom_patterns: dict[str, str] | None = None,
    ):
        """
        Initialize the PII scanner.
        
        Args:
            detect_types: Which PII types to detect (default: all)
            severity: Severity level for detected PII
            custom_patterns: Additional custom patterns {name: regex}
        """
        self.detect_types = detect_types or list(PIIType)
        self.severity = severity
        self.custom_patterns = custom_patterns or {}
        
        # Compile patterns
        self._compiled_patterns: dict[str, tuple[re.Pattern, str]] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for enabled PII types."""
        self._compiled_patterns = {}
        
        for pii_type in self.detect_types:
            if pii_type in self.PATTERNS:
                pattern, detail = self.PATTERNS[pii_type]
                self._compiled_patterns[pii_type.value] = (
                    re.compile(pattern, re.IGNORECASE),
                    detail,
                )
        
        # Add custom patterns
        for name, pattern in self.custom_patterns.items():
            self._compiled_patterns[name] = (
                re.compile(pattern, re.IGNORECASE),
                f"Custom PII pattern '{name}' matched",
            )
    
    @staticmethod
    def _luhn_check(card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm.
        
        Args:
            card_number: Card number (digits only)
            
        Returns:
            True if valid according to Luhn
        """
        digits = [int(d) for d in card_number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        
        # Luhn algorithm
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        
        return checksum % 10 == 0
    
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        """
        Scan text for PII.
        
        Args:
            text: The text to scan
            direction: Input or output direction
            
        Returns:
            List of detected PII issues
        """
        issues: list[Issue] = []
        
        for pii_name, (compiled_pattern, detail) in self._compiled_patterns.items():
            matches = list(compiled_pattern.finditer(text))
            
            for match in matches:
                matched_text = match.group()
                
                # Special handling for credit cards - validate with Luhn
                if pii_name == PIIType.CREDIT_CARD.value:
                    card_digits = "".join(c for c in matched_text if c.isdigit())
                    if not self._luhn_check(card_digits):
                        continue  # Skip invalid card numbers
                
                # Special handling for SSN - avoid false positives
                if pii_name == PIIType.SSN.value:
                    ssn_digits = "".join(c for c in matched_text if c.isdigit())
                    # SSN shouldn't start with 9, 666, or 000
                    if ssn_digits.startswith(("9", "666", "000")):
                        continue
                    # Area number (first 3 digits) shouldn't be 000
                    if ssn_digits[:3] == "000":
                        continue
                
                issues.append(Issue(
                    type=IssueType.PII_DETECTED,
                    severity=self.severity,
                    detail=detail,
                    span=(match.start(), match.end()),
                    scanner=self.name,
                    metadata={
                        "pii_type": pii_name,
                        "redacted_preview": self._redact_preview(matched_text, pii_name),
                    },
                ))
        
        return issues
    
    def _redact_preview(self, text: str, pii_type: str) -> str:
        """Create a partially redacted preview of the PII."""
        if len(text) <= 4:
            return "*" * len(text)
        return text[:2] + "*" * (len(text) - 4) + text[-2:]
    
    def redact(self, text: str) -> str:
        """
        Redact all detected PII from text.
        
        Args:
            text: The text to redact
            
        Returns:
            Text with PII replaced by placeholders
        """
        result = text
        
        # Collect all matches with their positions
        all_matches: list[tuple[int, int, str]] = []
        
        for pii_name, (compiled_pattern, _) in self._compiled_patterns.items():
            for match in compiled_pattern.finditer(text):
                # Determine placeholder
                try:
                    pii_type = PIIType(pii_name)
                    placeholder = self.REDACTION_PLACEHOLDERS.get(pii_type, f"[{pii_name.upper()}]")
                except ValueError:
                    placeholder = f"[{pii_name.upper()}]"
                
                all_matches.append((match.start(), match.end(), placeholder))
        
        # Sort by position (descending) to replace from end to start
        all_matches.sort(key=lambda x: x[0], reverse=True)
        
        # Replace matches
        for start, end, placeholder in all_matches:
            result = result[:start] + placeholder + result[end:]
        
        return result
