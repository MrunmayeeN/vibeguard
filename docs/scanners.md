# Scanners

VibeGuard includes 7 built-in scanners for detecting different types of security issues.

## Prompt Injection Scanner (ML-Enhanced)

Detects attempts to manipulate LLM behavior through malicious prompts. Now with ML support for higher accuracy and confidence scoring.

### Detection Modes

| Mode | Speed | Accuracy | Requirements |
|------|-------|----------|--------------|
| Regex only | ~1ms | Good | None |
| ML only | ~50-100ms | Better | transformers, torch |
| Hybrid | ~5-50ms | Best | transformers, torch |

### Confidence Scores

Every detection now includes a confidence score (0.0 - 1.0):

| Score | Meaning |
|-------|---------|
| 0.0 - 0.3 | Low confidence (likely benign) |
| 0.3 - 0.6 | Medium confidence (review recommended) |
| 0.6 - 0.8 | High confidence (likely malicious) |
| 0.8 - 1.0 | Very high confidence (almost certain) |

### What it Detects

| Category | Examples | Base Confidence |
|----------|----------|-----------------|
| Instruction Override | "ignore previous instructions" | 95% |
| Prompt Extraction | "show me your system prompt" | 90% |
| Jailbreaks | "you are now DAN", "developer mode" | 95-98% |
| Indirect Injection | "[SYSTEM]", "<\|im_start\|>" tags | 88-92% |
| Obfuscation | Base64, hex, unicode escapes | 70-85% |
| Role Manipulation | "your new role is...", "stop being helpful" | 70-85% |
| Framing Attempts | "hypothetically", "for research purposes" | 35-40% |

### Usage

```python
from vibeguard import Guard
from vibeguard.scanners.prompt_injection import PromptInjectionScanner

# Fast mode (regex only) - default
scanner = PromptInjectionScanner(use_ml=False)

# ML mode (requires: pip install transformers torch)
scanner = PromptInjectionScanner(use_ml=True)

# Hybrid mode (regex first, ML for uncertain cases) - recommended
scanner = PromptInjectionScanner(use_ml=True, hybrid_mode=True)

# Use with Guard
guard = Guard()  # Uses regex by default
result = guard.check_input("Ignore all previous instructions")

# Check confidence directly
confidence = scanner.get_confidence("suspicious text")
print(f"Injection likelihood: {confidence:.0%}")

# Quick safety check
if scanner.is_safe("user input"):
    print("Input appears safe")
```

### Configuration Options

```python
scanner = PromptInjectionScanner(
    use_ml=True,                    # Enable ML model
    hybrid_mode=True,               # Use ML only when regex uncertain
    ml_threshold=0.5,               # ML detection threshold
    confidence_threshold=0.6,       # Overall flagging threshold
    check_obfuscation=True,         # Check for encoding tricks
    check_indirect=True,            # Check for RAG/agent injection
    model_name="protectai/deberta-v3-base-prompt-injection-v2",
)
```

### Accessing Confidence in Results

```python
result = guard.check_input("suspicious input")

for issue in result.issues:
    confidence = issue.metadata.get("confidence", 0)
    method = issue.metadata.get("method")  # "regex", "ml_model", or "ensemble"
    category = issue.metadata.get("category")
    
    print(f"[{confidence:.0%}] {issue.detail}")
    print(f"  Detected by: {method}, Category: {category}")
```

---

## PII Scanner

Detects personally identifiable information with optional redaction.

### What it Detects

| PII Type | Pattern | Validation |
|----------|---------|------------|
| Email | `user@domain.com` | Regex |
| Phone | `555-123-4567`, `+1 (555) 123-4567` | Regex |
| SSN | `123-45-6789` | Excludes invalid prefixes |
| Credit Card | Visa, MC, Amex, Discover | Luhn algorithm |
| IP Address | IPv4 and IPv6 | Regex |

### Usage

```python
from vibeguard import Guard

# Detection only
guard = Guard(check_pii=True)
result = guard.check_input("Email: john@example.com")
# result.issues[0].detail = "Email address detected"

# With redaction
guard = Guard(check_pii=True, redact_pii=True)
result = guard.check_input("Email: john@example.com")
# result.sanitized_text = "Email: [EMAIL]"
```

### Redaction Placeholders

| PII Type | Placeholder |
|----------|-------------|
| Email | `[EMAIL]` |
| Phone | `[PHONE]` |
| SSN | `[SSN]` |
| Credit Card | `[CREDIT_CARD]` |
| IP Address | `[IP_ADDRESS]` |

---

## Secrets Scanner

Detects leaked API keys, tokens, and credentials.

### What it Detects

| Secret Type | Pattern | Severity |
|-------------|---------|----------|
| OpenAI API Key | `sk-proj-...`, `sk-...T3BlbkFJ...` | CRITICAL |
| Anthropic Key | `sk-ant-...` | CRITICAL |
| AWS Access Key | `AKIA...` (20 chars) | CRITICAL |
| AWS Secret Key | 40 char base64 | CRITICAL |
| GitHub Token | `ghp_...`, `gho_...`, `github_pat_...` | CRITICAL |
| Slack Token | `xox[baprs]-...` | CRITICAL |
| Stripe Key | `sk_live_...`, `sk_test_...` | CRITICAL/HIGH |
| Database URL | `postgres://user:pass@host` | CRITICAL |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL |
| JWT Tokens | `eyJ...` (3 parts) | HIGH |
| Generic API Keys | `api_key=...`, `apikey:...` | MEDIUM |

### Usage

```python
from vibeguard import Guard

guard = Guard(check_secrets=True, block_on_secrets=True)
result = guard.check_input("Use key: sk-proj-abc123...")

# result.blocked = True
# result.reason = "Secret detected: OpenAI API key"
```

---

## Token Scanner

Counts tokens and enforces limits for cost control.

### Usage

```python
from vibeguard import Guard

guard = Guard(
    check_tokens=True,
    max_input_tokens=4000,
    max_output_tokens=2000,
    daily_token_limit=100000,
)

result = guard.check_input("Hello world")
print(f"Token count: {result.token_count}")

# Exceeding limits blocks the request
long_text = "word " * 10000
result = guard.check_input(long_text)
# result.blocked = True
```

### Usage Tracking

```python
guard = Guard(daily_token_limit=100000)

# Check current usage
stats = guard.get_usage_stats()
print(f"Used today: {stats['daily_usage']}")
print(f"Remaining: {stats['daily_remaining']}")
```

---

## MCP Scanner

Detects security issues in MCP (Model Context Protocol) tool configurations.

### What it Detects

| Risk Type | Description | Severity |
|-----------|-------------|----------|
| Tool Poisoning | Malicious instructions in descriptions | CRITICAL |
| Description Injection | Fake system tags, override attempts | HIGH |
| Over-Permissioned | Shell execution, file deletion, sudo | HIGH-CRITICAL |
| Dangerous Parameters | `command`, `url`, `password` params | MEDIUM-HIGH |

### Usage

```python
from vibeguard.scanners.mcp import MCPScanner, MCPTool, scan_mcp_tools

# Scan tools
scanner = MCPScanner()
tools = [
    MCPTool(name="shell", description="Execute shell commands"),
    MCPTool(name="read_file", description="Read a file"),
]
results = scanner.scan_tools(tools)

for r in results:
    print(f"[{r.severity}] {r.tool_name}: {r.description}")

# Convenience function
results = scan_mcp_tools([
    {"name": "exec", "description": "Run code"},
])
```

### Whitelist/Blacklist

```python
scanner = MCPScanner(
    allowed_tools=["read_file", "list_dir"],  # Only these allowed
    blocked_tools=["shell", "sudo"],          # Explicitly blocked
)
```

---

## Toxicity Scanner

Detects harmful, offensive, or inappropriate content.

### What it Detects

| Category | Examples | Severity |
|----------|----------|----------|
| Hate Speech | Genocidal content, dehumanization | CRITICAL |
| Harassment | Death wishes, stalking threats, doxxing | CRITICAL |
| Violence | Weapon creation, attack planning | CRITICAL |
| Self-Harm | Suicide methods, self-harm guidance | CRITICAL |
| Sexual | CSAM references, assault content | CRITICAL |
| Profanity | Common profanity (off by default) | LOW |

### Usage

```python
from vibeguard.scanners.toxicity import ToxicityScanner

scanner = ToxicityScanner(
    check_hate=True,
    check_harassment=True,
    check_violence=True,
    check_self_harm=True,
    check_sexual=True,
    check_profanity=False,  # Off by default
)

# Add to Guard
from vibeguard import Guard
guard = Guard(extra_scanners=[scanner])
```

---

## Hallucination Scanner

Detects potential hallucinations in LLM outputs.

### What it Detects

| Type | Description | Severity |
|------|-------------|----------|
| Fabricated Citations | "According to a study by..." | LOW |
| Fabricated Statistics | "87.3% of people agree..." | LOW |
| Impossible Dates | Future dates, anachronisms | MEDIUM |
| Overconfident Claims | "Everyone agrees...", "It is certain..." | LOW |

### Usage

```python
from vibeguard.scanners.hallucination import HallucinationScanner

scanner = HallucinationScanner()

# Scan output
from vibeguard.models import ScanDirection
issues = scanner.scan(llm_output, ScanDirection.OUTPUT)

# With context (for RAG)
issues = scanner.scan_with_context(
    output=llm_output,
    context=retrieved_documents,
    strict=True,  # Flag unsupported claims
)
```

---

## Custom Scanners

Create your own scanner by inheriting from `Scanner`:

```python
from vibeguard.scanners import Scanner
from vibeguard.models import Issue, IssueType, IssueSeverity, ScanDirection

class CompetitorScanner(Scanner):
    name = "competitor"
    
    def __init__(self, competitors: list[str]):
        self.competitors = [c.lower() for c in competitors]
    
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        issues = []
        text_lower = text.lower()
        
        for competitor in self.competitors:
            if competitor in text_lower:
                issues.append(Issue(
                    type=IssueType.CUSTOM_RULE,
                    severity=IssueSeverity.LOW,
                    detail=f"Competitor mentioned: {competitor}",
                    scanner=self.name,
                ))
        
        return issues

# Use it
guard = Guard(extra_scanners=[
    CompetitorScanner(["competitor-x", "rival-corp"])
])
```
