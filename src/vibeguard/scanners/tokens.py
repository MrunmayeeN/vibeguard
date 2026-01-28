"""Token counting and cost control scanner."""

import re
from typing import ClassVar

from vibeguard.models import Issue, IssueSeverity, IssueType, ScanDirection
from vibeguard.scanners import Scanner


class TokenScanner(Scanner):
    """
    Estimates token count and enforces limits.
    
    Uses a simple heuristic for token estimation that works across
    most LLM tokenizers (GPT, Claude, etc.). For precise counting,
    use the tiktoken library with OpenAI models.
    """
    
    name: str = "token_counter"
    
    # Average characters per token for estimation
    # This is a conservative estimate that works across models
    CHARS_PER_TOKEN: ClassVar[float] = 4.0
    
    def __init__(
        self,
        max_input_tokens: int | None = None,
        max_output_tokens: int | None = None,
        warn_threshold: float = 0.8,  # Warn at 80% of limit
    ):
        """
        Initialize the token scanner.
        
        Args:
            max_input_tokens: Maximum allowed tokens for input
            max_output_tokens: Maximum allowed tokens for output
            warn_threshold: Percentage of limit at which to warn
        """
        self.max_input_tokens = max_input_tokens
        self.max_output_tokens = max_output_tokens
        self.warn_threshold = warn_threshold
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate the number of tokens in text.
        
        This uses a simple heuristic based on character count and word boundaries.
        For more accurate counting with OpenAI models, use tiktoken.
        
        Args:
            text: The text to count
            
        Returns:
            Estimated token count
        """
        if not text:
            return 0
        
        # Method 1: Character-based estimate
        char_estimate = len(text) / self.CHARS_PER_TOKEN
        
        # Method 2: Word-based estimate (rough, but helps with edge cases)
        words = len(re.findall(r'\b\w+\b', text))
        word_estimate = words * 1.3  # Average ~1.3 tokens per word
        
        # Take the average of both methods
        estimate = (char_estimate + word_estimate) / 2
        
        # Add some for special characters, punctuation
        special_chars = len(re.findall(r'[^\w\s]', text))
        estimate += special_chars * 0.5
        
        return int(estimate)
    
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        """
        Scan text for token limit violations.
        
        Args:
            text: The text to scan
            direction: Input or output direction
            
        Returns:
            List of token limit issues
        """
        issues: list[Issue] = []
        token_count = self.estimate_tokens(text)
        
        # Determine which limit to check
        if direction == ScanDirection.INPUT:
            max_tokens = self.max_input_tokens
            limit_type = "input"
        else:
            max_tokens = self.max_output_tokens
            limit_type = "output"
        
        if max_tokens is None:
            return issues
        
        # Check if over limit
        if token_count > max_tokens:
            issues.append(Issue(
                type=IssueType.TOKEN_LIMIT_EXCEEDED,
                severity=IssueSeverity.HIGH,
                detail=f"{limit_type.title()} exceeds token limit: {token_count} > {max_tokens}",
                scanner=self.name,
                metadata={
                    "token_count": token_count,
                    "limit": max_tokens,
                    "direction": limit_type,
                    "overage": token_count - max_tokens,
                },
            ))
        # Check if approaching limit
        elif token_count > max_tokens * self.warn_threshold:
            issues.append(Issue(
                type=IssueType.TOKEN_LIMIT_EXCEEDED,
                severity=IssueSeverity.LOW,
                detail=f"{limit_type.title()} approaching token limit: {token_count}/{max_tokens} ({int(token_count/max_tokens*100)}%)",
                scanner=self.name,
                metadata={
                    "token_count": token_count,
                    "limit": max_tokens,
                    "direction": limit_type,
                    "percentage": token_count / max_tokens,
                },
            ))
        
        return issues


class UsageTracker:
    """
    Tracks token usage across sessions for cost control.
    
    This is a simple in-memory tracker. For production, you'd want
    to persist this to a database.
    """
    
    def __init__(
        self,
        daily_limit: int | None = None,
        hourly_limit: int | None = None,
        per_request_limit: int | None = None,
    ):
        """
        Initialize the usage tracker.
        
        Args:
            daily_limit: Maximum tokens per day
            hourly_limit: Maximum tokens per hour
            per_request_limit: Maximum tokens per request
        """
        self.daily_limit = daily_limit
        self.hourly_limit = hourly_limit
        self.per_request_limit = per_request_limit
        
        # In-memory tracking (reset on restart)
        self._daily_usage: dict[str, int] = {}  # date -> tokens
        self._hourly_usage: dict[str, int] = {}  # datetime_hour -> tokens
    
    def record_usage(self, tokens: int, session_id: str | None = None) -> None:
        """Record token usage."""
        from datetime import datetime
        
        now = datetime.utcnow()
        date_key = now.strftime("%Y-%m-%d")
        hour_key = now.strftime("%Y-%m-%d-%H")
        
        self._daily_usage[date_key] = self._daily_usage.get(date_key, 0) + tokens
        self._hourly_usage[hour_key] = self._hourly_usage.get(hour_key, 0) + tokens
    
    def check_limits(self, requested_tokens: int) -> tuple[bool, str | None]:
        """
        Check if usage limits would be exceeded.
        
        Args:
            requested_tokens: Tokens being requested
            
        Returns:
            Tuple of (allowed, reason_if_denied)
        """
        from datetime import datetime
        
        now = datetime.utcnow()
        date_key = now.strftime("%Y-%m-%d")
        hour_key = now.strftime("%Y-%m-%d-%H")
        
        # Check per-request limit
        if self.per_request_limit and requested_tokens > self.per_request_limit:
            return False, f"Request exceeds per-request limit: {requested_tokens} > {self.per_request_limit}"
        
        # Check hourly limit
        if self.hourly_limit:
            current_hourly = self._hourly_usage.get(hour_key, 0)
            if current_hourly + requested_tokens > self.hourly_limit:
                return False, f"Would exceed hourly limit: {current_hourly + requested_tokens} > {self.hourly_limit}"
        
        # Check daily limit
        if self.daily_limit:
            current_daily = self._daily_usage.get(date_key, 0)
            if current_daily + requested_tokens > self.daily_limit:
                return False, f"Would exceed daily limit: {current_daily + requested_tokens} > {self.daily_limit}"
        
        return True, None
    
    def get_usage_stats(self) -> dict:
        """Get current usage statistics."""
        from datetime import datetime
        
        now = datetime.utcnow()
        date_key = now.strftime("%Y-%m-%d")
        hour_key = now.strftime("%Y-%m-%d-%H")
        
        return {
            "daily_usage": self._daily_usage.get(date_key, 0),
            "daily_limit": self.daily_limit,
            "daily_remaining": (self.daily_limit - self._daily_usage.get(date_key, 0)) if self.daily_limit else None,
            "hourly_usage": self._hourly_usage.get(hour_key, 0),
            "hourly_limit": self.hourly_limit,
            "hourly_remaining": (self.hourly_limit - self._hourly_usage.get(hour_key, 0)) if self.hourly_limit else None,
        }
