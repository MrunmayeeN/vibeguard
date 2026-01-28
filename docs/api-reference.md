# API Reference

## Core Classes

### Guard

The main class for scanning inputs and outputs.

```python
class Guard:
    def __init__(
        self,
        check_prompt_injection: bool = True,
        check_pii: bool = True,
        check_secrets: bool = True,
        check_tokens: bool = True,
        redact_pii: bool = False,
        redact_secrets: bool = False,
        block_on_injection: bool = True,
        block_on_secrets: bool = True,
        max_input_tokens: int | None = None,
        max_output_tokens: int | None = None,
        daily_token_limit: int | None = None,
        policy: Policy | None = None,
        audit_log: str | Path | None = None,
        log_content: bool = False,
        audit_webhook: str | None = None,
        extra_scanners: list[Scanner] | None = None,
        session_id: str | None = None,
    ): ...
    
    def check_input(self, text: str, metadata: dict | None = None) -> CheckResult: ...
    def check_output(self, text: str, metadata: dict | None = None) -> CheckResult: ...
    def get_usage_stats(self) -> dict[str, Any]: ...
    
    @classmethod
    def from_config(cls, config_path: str | Path) -> "Guard": ...
    
    def close(self) -> None: ...
```

### CheckResult

Result of scanning text.

```python
class CheckResult(BaseModel):
    original_text: str
    sanitized_text: str
    blocked: bool = False
    reason: str | None = None
    issues: list[Issue] = []
    token_count: int = 0
    scan_direction: ScanDirection = ScanDirection.INPUT
    timestamp: datetime
    session_id: str | None = None
    metadata: dict[str, Any] = {}
    
    @property
    def has_issues(self) -> bool: ...
    
    @property
    def highest_severity(self) -> IssueSeverity | None: ...
    
    def get_issues_by_type(self, issue_type: IssueType) -> list[Issue]: ...
    def get_issues_by_severity(self, severity: IssueSeverity) -> list[Issue]: ...
```

### Issue

A detected security issue.

```python
class Issue(BaseModel):
    type: IssueType
    severity: IssueSeverity
    detail: str
    span: tuple[int, int] | None = None  # Position in text
    scanner: str = "unknown"
    metadata: dict[str, Any] = {}
```

---

## Enums

### IssueType

```python
class IssueType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_DETECTED = "pii_detected"
    SECRET_DETECTED = "secret_detected"
    TOXIC_CONTENT = "toxic_content"
    TOKEN_LIMIT_EXCEEDED = "token_limit_exceeded"
    CUSTOM_RULE = "custom_rule"
    MCP_TOOL_POISONING = "mcp_tool_poisoning"
```

### IssueSeverity

```python
class IssueSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

### ScanDirection

```python
class ScanDirection(str, Enum):
    INPUT = "input"
    OUTPUT = "output"
```

---

## Policy Classes

### Policy

```python
class Policy(BaseModel):
    name: str = "default"
    rules: list[Rule] = []
    default_action_on_issues: Action = Action.WARN
    
    def evaluate(self, result: CheckResult) -> tuple[Action, str | None]: ...
    
    @classmethod
    def strict(cls) -> "Policy": ...
    
    @classmethod
    def permissive(cls) -> "Policy": ...
    
    @classmethod
    def redact_pii(cls) -> "Policy": ...
```

### Rule

```python
class Rule(BaseModel):
    name: str
    issue_types: list[IssueType] | None = None
    min_severity: IssueSeverity | None = None
    max_severity: IssueSeverity | None = None
    scanners: list[str] | None = None
    action: Action = Action.WARN
    priority: int = 0
    message: str | None = None
    condition: Callable[[CheckResult], bool] | None = None
    
    def matches(self, result: CheckResult) -> bool: ...
```

### Action

```python
class Action(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"
```

---

## Scanner Classes

### Scanner (Base)

```python
class Scanner(ABC):
    name: str = "base_scanner"
    enabled: bool = True
    
    @abstractmethod
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]: ...
    
    def configure(self, **kwargs) -> None: ...
```

### PromptInjectionScanner

```python
class PromptInjectionScanner(Scanner):
    name = "prompt_injection"
```

### PIIScanner

```python
class PIIScanner(Scanner):
    name = "pii"
    
    def redact(self, text: str) -> str: ...
```

### SecretsScanner

```python
class SecretsScanner(Scanner):
    name = "secrets"
    
    def redact(self, text: str) -> str: ...
```

### TokenScanner

```python
class TokenScanner(Scanner):
    name = "tokens"
    
    def __init__(
        self,
        max_input_tokens: int | None = None,
        max_output_tokens: int | None = None,
    ): ...
    
    def estimate_tokens(self, text: str) -> int: ...
```

### MCPScanner

```python
class MCPScanner(Scanner):
    name = "mcp"
    
    def __init__(
        self,
        check_poisoning: bool = True,
        check_permissions: bool = True,
        check_parameters: bool = True,
        allowed_tools: list[str] | None = None,
        blocked_tools: list[str] | None = None,
    ): ...
    
    def scan_tools(self, tools: list[MCPTool]) -> list[MCPScanResult]: ...
    def scan_config(self, config: dict) -> list[MCPScanResult]: ...
```

### ToxicityScanner

```python
class ToxicityScanner(Scanner):
    name = "toxicity"
    
    def __init__(
        self,
        check_hate: bool = True,
        check_harassment: bool = True,
        check_violence: bool = True,
        check_self_harm: bool = True,
        check_sexual: bool = True,
        check_profanity: bool = False,
        min_severity: IssueSeverity = IssueSeverity.MEDIUM,
        use_ml_model: bool = False,
    ): ...
```

### HallucinationScanner

```python
class HallucinationScanner(Scanner):
    name = "hallucination"
    
    def __init__(
        self,
        check_citations: bool = True,
        check_statistics: bool = True,
        check_dates: bool = True,
        check_confidence: bool = True,
        confidence_threshold: float = 0.6,
    ): ...
    
    def scan_with_context(
        self,
        output: str,
        context: str | list[str],
        strict: bool = False,
    ) -> list[Issue]: ...
```

---

## Authorization Classes

### ActionAuthorizer

```python
class ActionAuthorizer:
    def __init__(
        self,
        auto_approve_risk: ActionRisk = ActionRisk.LOW,
        require_approval_risk: ActionRisk = ActionRisk.HIGH,
        auto_deny_risk: ActionRisk | None = None,
        approval_timeout: timedelta = timedelta(minutes=5),
        approval_callback: Callable[[ApprovalRequest], None] | None = None,
        rate_limits: dict[ActionCategory, tuple[int, timedelta]] | None = None,
        audit_log: str | Path | None = None,
        classifier: ActionClassifier | None = None,
    ): ...
    
    def authorize(
        self,
        action_name: str,
        parameters: dict | None = None,
        description: str | None = None,
    ) -> ActionResult: ...
    
    def approve(self, action_id: str, approved_by: str = "human") -> bool: ...
    def deny(self, action_id: str, reason: str, denied_by: str = "human") -> bool: ...
    def check_approval_status(self, action_id: str) -> ApprovalStatus | None: ...
    def wait_for_approval(self, request: ApprovalRequest) -> ApprovalStatus: ...
    def get_pending_approvals(self) -> list[ApprovalRequest]: ...
```

### ActionRisk

```python
class ActionRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

### ActionCategory

```python
class ActionCategory(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK = "network"
    FINANCIAL = "financial"
    COMMUNICATION = "communication"
    AUTHENTICATION = "authentication"
    SYSTEM = "system"
```

---

## Integration Classes

### GuardedOpenAI

```python
class GuardedOpenAI:
    def __init__(
        self,
        guard: Guard | None = None,
        api_key: str | None = None,
        **openai_kwargs,
    ): ...
    
    # Same interface as openai.OpenAI
    chat: _GuardedChat
```

### GuardedAnthropic

```python
class GuardedAnthropic:
    def __init__(
        self,
        guard: Guard | None = None,
        api_key: str | None = None,
        **anthropic_kwargs,
    ): ...
    
    # Same interface as anthropic.Anthropic
    messages: _GuardedMessages
```

### VibeGuardCallback

```python
class VibeGuardCallback:
    def __init__(
        self,
        guard: Guard | None = None,
        block_on_issues: bool = True,
        scan_prompts: bool = True,
        scan_outputs: bool = True,
        scan_tool_inputs: bool = True,
        scan_tool_outputs: bool = True,
    ): ...
    
    def get_results(self) -> list[CheckResult]: ...
    def clear_results(self) -> None: ...
```

---

## Dashboard Functions

```python
def create_app(
    audit_log_path: str | Path | None = None,
    authorizer: ActionAuthorizer | None = None,
) -> Flask: ...

def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    audit_log_path: str | Path | None = None,
    authorizer: ActionAuthorizer | None = None,
    debug: bool = False,
) -> None: ...
```
