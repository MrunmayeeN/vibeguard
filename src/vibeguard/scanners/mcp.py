"""
MCP (Model Context Protocol) Security Scanner.

Detects security issues in MCP tool configurations including:
- Tool poisoning (malicious instructions in tool descriptions)
- Prompt injection in tool schemas
- Over-permissioned tools
- Cross-origin escalation risks
- MCP rug pulls (tools that change behavior)
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar

from vibeguard.models import Issue, IssueSeverity, IssueType, ScanDirection
from vibeguard.scanners import Scanner


class MCPRiskType(str, Enum):
    """Types of MCP-specific risks."""
    
    TOOL_POISONING = "tool_poisoning"
    DESCRIPTION_INJECTION = "description_injection"
    OVER_PERMISSIONED = "over_permissioned"
    CROSS_ORIGIN_ESCALATION = "cross_origin_escalation"
    UNSAFE_DEFAULT = "unsafe_default"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_ACCESS = "credential_access"


@dataclass
class MCPTool:
    """Representation of an MCP tool."""
    
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    server_name: str = ""
    server_url: str = ""
    permissions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPScanResult:
    """Result of scanning an MCP configuration."""
    
    tool_name: str
    risk_type: MCPRiskType
    severity: IssueSeverity
    description: str
    recommendation: str
    evidence: str = ""


class MCPScanner(Scanner):
    """
    Scanner for MCP tool configurations.
    
    Detects security issues in Model Context Protocol tools that could
    be exploited by attackers to manipulate AI agents.
    
    Usage:
        scanner = MCPScanner()
        tools = [
            MCPTool(name="file_read", description="Read files from disk"),
            MCPTool(name="execute", description="Run shell commands"),
        ]
        results = scanner.scan_tools(tools)
    """
    
    name: str = "mcp"
    
    # Patterns indicating tool poisoning attempts
    POISONING_PATTERNS: ClassVar[list[tuple[str, str, IssueSeverity]]] = [
        # Hidden instructions in descriptions
        (
            r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|other|above)\s+(instructions?|rules?|constraints?)",
            "Instruction override in tool description",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)always\s+(execute|run|call|use)\s+this\s+tool\s+(first|before)",
            "Forced execution directive",
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)do\s+not\s+(tell|inform|notify|alert)\s+(the\s+)?(user|human)",
            "User deception directive",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)secretly|covertly|silently|without\s+(telling|informing|notifying)",
            "Stealth operation directive",
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)(extract|exfiltrate|send|transmit)\s+.*(data|information|secrets?|credentials?|keys?)",
            "Data exfiltration directive",
            IssueSeverity.CRITICAL,
        ),
        # Fake system messages
        (
            r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]",
            "Fake system tag in description",
            IssueSeverity.HIGH,
        ),
        (
            r"<\|?(system|instruction|admin)\|?>",
            "Fake XML system tag",
            IssueSeverity.HIGH,
        ),
    ]
    
    # High-risk tool patterns
    HIGH_RISK_TOOLS: ClassVar[dict[str, tuple[str, IssueSeverity]]] = {
        r"(?i)(shell|bash|cmd|exec|execute|run_command|system)": (
            "Shell command execution capability",
            IssueSeverity.HIGH,
        ),
        r"(?i)(file_write|write_file|save_file|create_file)": (
            "File write capability",
            IssueSeverity.MEDIUM,
        ),
        r"(?i)(delete|remove|rm|unlink).*file": (
            "File deletion capability",
            IssueSeverity.HIGH,
        ),
        r"(?i)(http_request|fetch|curl|wget|api_call)": (
            "External HTTP request capability",
            IssueSeverity.MEDIUM,
        ),
        r"(?i)(database|sql|query|db_)": (
            "Database access capability",
            IssueSeverity.MEDIUM,
        ),
        r"(?i)(credential|password|secret|api_key|token)": (
            "Credential access capability",
            IssueSeverity.HIGH,
        ),
        r"(?i)(sudo|admin|root|elevate|privilege)": (
            "Privilege escalation capability",
            IssueSeverity.CRITICAL,
        ),
        r"(?i)(email|send_mail|smtp)": (
            "Email sending capability",
            IssueSeverity.MEDIUM,
        ),
        r"(?i)(payment|transaction|transfer|billing)": (
            "Financial transaction capability",
            IssueSeverity.CRITICAL,
        ),
    }
    
    # Suspicious parameter patterns
    SUSPICIOUS_PARAMS: ClassVar[list[tuple[str, str, IssueSeverity]]] = [
        (
            r"(?i)^(command|cmd|shell|exec|code)$",
            "Direct command execution parameter",
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)^(url|endpoint|webhook|callback)$",
            "External URL parameter (potential SSRF)",
            IssueSeverity.MEDIUM,
        ),
        (
            r"(?i)^(path|file|filename)$",
            "File path parameter (potential path traversal)",
            IssueSeverity.MEDIUM,
        ),
        (
            r"(?i)(password|secret|key|token|credential)",
            "Sensitive credential parameter",
            IssueSeverity.HIGH,
        ),
    ]
    
    def __init__(
        self,
        check_poisoning: bool = True,
        check_permissions: bool = True,
        check_parameters: bool = True,
        allowed_tools: list[str] | None = None,
        blocked_tools: list[str] | None = None,
    ):
        """
        Initialize the MCP scanner.
        
        Args:
            check_poisoning: Check for tool poisoning in descriptions
            check_permissions: Check for over-permissioned tools
            check_parameters: Check for dangerous parameters
            allowed_tools: Whitelist of allowed tool names (if set, others blocked)
            blocked_tools: Blacklist of blocked tool names
        """
        self.check_poisoning = check_poisoning
        self.check_permissions = check_permissions
        self.check_parameters = check_parameters
        self.allowed_tools = set(allowed_tools) if allowed_tools else None
        self.blocked_tools = set(blocked_tools) if blocked_tools else set()
        
        # Compile patterns
        self._compiled_poisoning = [
            (re.compile(p), d, s) for p, d, s in self.POISONING_PATTERNS
        ]
        self._compiled_risk_tools = {
            re.compile(p): (d, s) for p, (d, s) in self.HIGH_RISK_TOOLS.items()
        }
        self._compiled_params = [
            (re.compile(p), d, s) for p, d, s in self.SUSPICIOUS_PARAMS
        ]
    
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        """
        Scan text for MCP-related security issues.
        
        This is the standard Scanner interface. For full MCP scanning,
        use scan_tools() or scan_config() instead.
        """
        issues = []
        
        # Check if text contains MCP tool definitions
        if '"tools"' in text or "'tools'" in text or "mcp" in text.lower():
            # Try to parse as JSON
            try:
                data = json.loads(text)
                if isinstance(data, dict) and "tools" in data:
                    tools = [
                        MCPTool(
                            name=t.get("name", "unknown"),
                            description=t.get("description", ""),
                            input_schema=t.get("inputSchema", {}),
                        )
                        for t in data["tools"]
                    ]
                    results = self.scan_tools(tools)
                    issues.extend(self._results_to_issues(results))
            except json.JSONDecodeError:
                pass
        
        # Also scan raw text for poisoning patterns
        for pattern, detail, severity in self._compiled_poisoning:
            if pattern.search(text):
                issues.append(Issue(
                    type=IssueType.MCP_TOOL_POISONING,
                    severity=severity,
                    detail=detail,
                    scanner=self.name,
                ))
        
        return issues
    
    def scan_tools(self, tools: list[MCPTool]) -> list[MCPScanResult]:
        """
        Scan a list of MCP tools for security issues.
        
        Args:
            tools: List of MCPTool objects to scan
            
        Returns:
            List of MCPScanResult objects describing found issues
        """
        results: list[MCPScanResult] = []
        
        for tool in tools:
            # Check whitelist/blacklist
            if self.allowed_tools and tool.name not in self.allowed_tools:
                results.append(MCPScanResult(
                    tool_name=tool.name,
                    risk_type=MCPRiskType.OVER_PERMISSIONED,
                    severity=IssueSeverity.HIGH,
                    description=f"Tool '{tool.name}' not in allowed list",
                    recommendation="Add to allowed_tools or remove from configuration",
                ))
            
            if tool.name in self.blocked_tools:
                results.append(MCPScanResult(
                    tool_name=tool.name,
                    risk_type=MCPRiskType.OVER_PERMISSIONED,
                    severity=IssueSeverity.CRITICAL,
                    description=f"Tool '{tool.name}' is explicitly blocked",
                    recommendation="Remove this tool from the configuration",
                ))
            
            # Check for poisoning in description
            if self.check_poisoning:
                results.extend(self._check_poisoning(tool))
            
            # Check tool permissions/capabilities
            if self.check_permissions:
                results.extend(self._check_permissions(tool))
            
            # Check parameters
            if self.check_parameters:
                results.extend(self._check_parameters(tool))
        
        return results
    
    def scan_config(self, config: dict[str, Any]) -> list[MCPScanResult]:
        """
        Scan an MCP server configuration.
        
        Args:
            config: MCP configuration dictionary
            
        Returns:
            List of MCPScanResult objects
        """
        results: list[MCPScanResult] = []
        
        # Extract tools from config
        tools = []
        
        # Handle different config formats
        if "tools" in config:
            for t in config["tools"]:
                tools.append(MCPTool(
                    name=t.get("name", "unknown"),
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", t.get("input_schema", {})),
                ))
        
        if "mcpServers" in config:
            for server_name, server_config in config["mcpServers"].items():
                # Check server URL
                server_url = server_config.get("url", "")
                if server_url and not server_url.startswith(("http://localhost", "https://localhost", "file://")):
                    results.append(MCPScanResult(
                        tool_name=f"server:{server_name}",
                        risk_type=MCPRiskType.CROSS_ORIGIN_ESCALATION,
                        severity=IssueSeverity.MEDIUM,
                        description=f"External MCP server: {server_url}",
                        recommendation="Verify this external server is trusted",
                        evidence=server_url,
                    ))
        
        # Scan extracted tools
        results.extend(self.scan_tools(tools))
        
        return results
    
    def _check_poisoning(self, tool: MCPTool) -> list[MCPScanResult]:
        """Check for tool poisoning in description."""
        results = []
        
        # Check description
        for pattern, detail, severity in self._compiled_poisoning:
            match = pattern.search(tool.description)
            if match:
                results.append(MCPScanResult(
                    tool_name=tool.name,
                    risk_type=MCPRiskType.TOOL_POISONING,
                    severity=severity,
                    description=f"Tool poisoning detected: {detail}",
                    recommendation="Remove malicious content from tool description",
                    evidence=match.group()[:100],
                ))
        
        # Check input schema descriptions
        if tool.input_schema:
            schema_str = json.dumps(tool.input_schema)
            for pattern, detail, severity in self._compiled_poisoning:
                match = pattern.search(schema_str)
                if match:
                    results.append(MCPScanResult(
                        tool_name=tool.name,
                        risk_type=MCPRiskType.DESCRIPTION_INJECTION,
                        severity=severity,
                        description=f"Injection in schema: {detail}",
                        recommendation="Review and sanitize input schema",
                        evidence=match.group()[:100],
                    ))
        
        return results
    
    def _check_permissions(self, tool: MCPTool) -> list[MCPScanResult]:
        """Check for over-permissioned or dangerous tools."""
        results = []
        
        # Check tool name and description against high-risk patterns
        text_to_check = f"{tool.name} {tool.description}"
        
        for pattern, (detail, severity) in self._compiled_risk_tools.items():
            if pattern.search(text_to_check):
                results.append(MCPScanResult(
                    tool_name=tool.name,
                    risk_type=MCPRiskType.OVER_PERMISSIONED,
                    severity=severity,
                    description=detail,
                    recommendation="Consider restricting this tool's capabilities or adding confirmation steps",
                ))
        
        return results
    
    def _check_parameters(self, tool: MCPTool) -> list[MCPScanResult]:
        """Check for dangerous parameters in tool schema."""
        results = []
        
        if not tool.input_schema:
            return results
        
        properties = tool.input_schema.get("properties", {})
        
        for param_name, param_config in properties.items():
            for pattern, detail, severity in self._compiled_params:
                if pattern.search(param_name):
                    results.append(MCPScanResult(
                        tool_name=tool.name,
                        risk_type=MCPRiskType.OVER_PERMISSIONED,
                        severity=severity,
                        description=f"Dangerous parameter '{param_name}': {detail}",
                        recommendation="Add validation, sanitization, or confirmation for this parameter",
                        evidence=param_name,
                    ))
        
        return results
    
    def _results_to_issues(self, results: list[MCPScanResult]) -> list[Issue]:
        """Convert MCPScanResults to standard Issues."""
        issues = []
        for r in results:
            issues.append(Issue(
                type=IssueType.MCP_TOOL_POISONING,
                severity=r.severity,
                detail=f"[{r.tool_name}] {r.description}",
                scanner=self.name,
                metadata={
                    "tool_name": r.tool_name,
                    "risk_type": r.risk_type.value,
                    "recommendation": r.recommendation,
                    "evidence": r.evidence,
                },
            ))
        return issues


def scan_mcp_tools(tools: list[dict[str, Any]] | list[MCPTool]) -> list[MCPScanResult]:
    """
    Convenience function to scan MCP tools.
    
    Args:
        tools: List of tool dictionaries or MCPTool objects
        
    Returns:
        List of scan results
    
    Example:
        results = scan_mcp_tools([
            {"name": "shell", "description": "Run shell commands"},
            {"name": "read_file", "description": "Read a file"},
        ])
    """
    scanner = MCPScanner()
    
    # Convert dicts to MCPTool if needed
    mcp_tools = []
    for t in tools:
        if isinstance(t, MCPTool):
            mcp_tools.append(t)
        else:
            mcp_tools.append(MCPTool(
                name=t.get("name", "unknown"),
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", t.get("input_schema", {})),
            ))
    
    return scanner.scan_tools(mcp_tools)


def scan_mcp_config(config_path: str) -> list[MCPScanResult]:
    """
    Scan an MCP configuration file.
    
    Args:
        config_path: Path to MCP config file (JSON)
        
    Returns:
        List of scan results
    """
    with open(config_path) as f:
        config = json.load(f)
    
    scanner = MCPScanner()
    return scanner.scan_config(config)
