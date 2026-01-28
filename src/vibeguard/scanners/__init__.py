"""Base scanner interface for VibeGuard."""

from abc import ABC, abstractmethod

from vibeguard.models import Issue, ScanDirection


class Scanner(ABC):
    """
    Base class for all security scanners.
    
    To create a custom scanner, inherit from this class and implement
    the `scan` method.
    
    Example:
        class MyScanner(Scanner):
            name = "my_scanner"
            
            def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
                issues = []
                if "bad_word" in text:
                    issues.append(Issue(
                        type=IssueType.CUSTOM_RULE,
                        severity=IssueSeverity.MEDIUM,
                        detail="Found bad word",
                        scanner=self.name
                    ))
                return issues
    """
    
    name: str = "base_scanner"
    enabled: bool = True
    
    @abstractmethod
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        """
        Scan text for security issues.
        
        Args:
            text: The text to scan
            direction: Whether this is input to LLM or output from LLM
            
        Returns:
            List of detected issues (empty if none found)
        """
        pass
    
    def configure(self, **kwargs) -> None:
        """
        Configure the scanner with custom settings.
        
        Override this method to accept configuration options.
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)


# Import scanners for convenient access
from vibeguard.scanners.prompt_injection import PromptInjectionScanner
from vibeguard.scanners.pii import PIIScanner
from vibeguard.scanners.secrets import SecretsScanner
from vibeguard.scanners.tokens import TokenScanner, UsageTracker
from vibeguard.scanners.mcp import MCPScanner, MCPTool, scan_mcp_tools
from vibeguard.scanners.toxicity import ToxicityScanner, ToxicityCategory
from vibeguard.scanners.hallucination import HallucinationScanner, HallucinationType

__all__ = [
    "Scanner",
    "PromptInjectionScanner",
    "PIIScanner", 
    "SecretsScanner",
    "TokenScanner",
    "UsageTracker",
    "MCPScanner",
    "MCPTool",
    "scan_mcp_tools",
    "ToxicityScanner",
    "ToxicityCategory",
    "HallucinationScanner",
    "HallucinationType",
]
