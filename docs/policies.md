# Policy Engine

The policy engine lets you define custom rules for handling security issues.

## Basic Concepts

- **Policy**: A collection of rules that determine how to handle issues
- **Rule**: A condition + action (e.g., "if HIGH severity → BLOCK")
- **Action**: What to do when a rule matches (ALLOW, WARN, BLOCK, REDACT)

## Preset Policies

### Strict Policy (Default)

Blocks HIGH and CRITICAL issues, warns on MEDIUM.

```python
from vibeguard import Guard
from vibeguard.policies import Policy

guard = Guard(policy=Policy.strict())
```

### Permissive Policy

Only blocks CRITICAL issues.

```python
guard = Guard(policy=Policy.permissive())
```

### Redact PII Policy

Redacts PII, blocks secrets.

```python
guard = Guard(policy=Policy.redact_pii())
```

## Custom Policies

### Creating Rules

```python
from vibeguard import Policy, Rule, Action, IssueType, IssueSeverity

# Create rules
rule1 = Rule(
    name="block_critical",
    min_severity=IssueSeverity.CRITICAL,
    action=Action.BLOCK,
    priority=100,  # Higher priority = evaluated first
)

rule2 = Rule(
    name="block_secrets",
    issue_types=[IssueType.SECRET_DETECTED],
    action=Action.BLOCK,
    priority=90,
)

rule3 = Rule(
    name="redact_pii",
    issue_types=[IssueType.PII_DETECTED],
    action=Action.REDACT,
    priority=80,
)

rule4 = Rule(
    name="warn_injection",
    issue_types=[IssueType.PROMPT_INJECTION],
    min_severity=IssueSeverity.MEDIUM,
    action=Action.WARN,
    priority=70,
)

# Create policy
policy = Policy(
    name="my_policy",
    rules=[rule1, rule2, rule3, rule4],
    default_action_on_issues=Action.ALLOW,
)

guard = Guard(policy=policy)
```

### Rule Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | str | Unique rule identifier |
| `issue_types` | list[IssueType] | Issue types to match (None = all) |
| `min_severity` | IssueSeverity | Minimum severity to match |
| `max_severity` | IssueSeverity | Maximum severity to match |
| `scanners` | list[str] | Scanner names to match |
| `action` | Action | Action to take |
| `priority` | int | Evaluation order (higher first) |
| `message` | str | Custom message for this rule |
| `condition` | Callable | Custom condition function |

### Actions

| Action | Description |
|--------|-------------|
| `ALLOW` | Allow the request to proceed |
| `WARN` | Log warning but allow |
| `BLOCK` | Block the request |
| `REDACT` | Redact sensitive content |
| `REQUIRE_APPROVAL` | Require human approval |

## Custom Conditions

For complex logic, use a custom condition function:

```python
from vibeguard import Policy, Rule, Action, CheckResult

def high_risk_condition(result: CheckResult) -> bool:
    """Block if multiple high-severity issues."""
    high_issues = [
        i for i in result.issues 
        if i.severity in [IssueSeverity.HIGH, IssueSeverity.CRITICAL]
    ]
    return len(high_issues) >= 2

rule = Rule(
    name="multiple_high_risk",
    action=Action.BLOCK,
    condition=high_risk_condition,
    message="Multiple high-risk issues detected",
)
```

## Policy Evaluation

Rules are evaluated in priority order (highest first). The first matching rule determines the action.

```python
policy = Policy(
    rules=[
        Rule(name="r1", min_severity=IssueSeverity.CRITICAL, action=Action.BLOCK, priority=100),
        Rule(name="r2", min_severity=IssueSeverity.HIGH, action=Action.WARN, priority=50),
        Rule(name="r3", action=Action.ALLOW, priority=0),  # Default fallback
    ]
)

# Evaluation order: r1 → r2 → r3
# If CRITICAL issue: r1 matches → BLOCK
# If HIGH issue: r2 matches → WARN
# Otherwise: r3 matches → ALLOW
```

## Examples

### E-commerce Policy

```python
policy = Policy(
    name="ecommerce",
    rules=[
        # Always block secrets
        Rule(
            name="block_secrets",
            issue_types=[IssueType.SECRET_DETECTED],
            action=Action.BLOCK,
            priority=100,
        ),
        # Redact credit cards
        Rule(
            name="redact_payment",
            issue_types=[IssueType.PII_DETECTED],
            action=Action.REDACT,
            priority=90,
            condition=lambda r: any("credit" in i.detail.lower() for i in r.issues),
        ),
        # Block prompt injection
        Rule(
            name="block_injection",
            issue_types=[IssueType.PROMPT_INJECTION],
            min_severity=IssueSeverity.HIGH,
            action=Action.BLOCK,
            priority=80,
        ),
    ],
)
```

### Healthcare Policy (HIPAA-aware)

```python
policy = Policy(
    name="healthcare_hipaa",
    rules=[
        # Block all PII - HIPAA requires protection
        Rule(
            name="block_phi",
            issue_types=[IssueType.PII_DETECTED],
            action=Action.BLOCK,
            message="Protected Health Information detected",
            priority=100,
        ),
        # Block any secrets
        Rule(
            name="block_secrets",
            issue_types=[IssueType.SECRET_DETECTED],
            action=Action.BLOCK,
            priority=100,
        ),
        # Block all prompt injection attempts
        Rule(
            name="block_injection",
            issue_types=[IssueType.PROMPT_INJECTION, IssueType.JAILBREAK],
            action=Action.BLOCK,
            priority=90,
        ),
    ],
    default_action_on_issues=Action.BLOCK,  # Block anything suspicious
)
```

### Logging-Only Policy

For monitoring without blocking:

```python
policy = Policy(
    name="monitor_only",
    rules=[
        Rule(
            name="warn_all",
            action=Action.WARN,
            priority=0,
        ),
    ],
    default_action_on_issues=Action.ALLOW,
)

guard = Guard(
    policy=policy,
    block_on_injection=False,
    block_on_secrets=False,
    audit_log="monitor.jsonl",
)
```
