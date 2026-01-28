# Agent Authorization

The authorization system provides human-in-the-loop controls for AI agent actions.

## Overview

When AI agents can take real-world actions (send emails, make purchases, delete files), you need controls to prevent catastrophic mistakes. The authorization system:

- **Classifies actions** by risk level
- **Auto-approves** low-risk actions
- **Requires approval** for high-risk actions
- **Rate limits** actions by category
- **Logs everything** for audit trails

## Basic Usage

```python
from vibeguard.authorization import ActionAuthorizer

authorizer = ActionAuthorizer()

# Check if action is allowed
result = authorizer.authorize(
    action_name="send_email",
    parameters={"to": "user@example.com", "subject": "Hello"},
)

if result.authorized:
    # Proceed with action
    send_email(...)
elif result.requires_approval:
    # Wait for human approval
    print(f"Action requires approval: {result.action.id}")
else:
    # Action denied
    print(f"Denied: {result.reason}")
```

## Risk Levels

Actions are automatically classified into risk levels:

| Level | Description | Default Behavior |
|-------|-------------|------------------|
| LOW | Safe actions (read operations) | Auto-approve |
| MEDIUM | Potentially risky (write operations) | Auto-approve with logging |
| HIGH | Risky actions (delete, external calls) | Require approval |
| CRITICAL | Dangerous actions (shell, payments) | Require approval or deny |

## Action Categories

| Category | Examples | Default Risk |
|----------|----------|--------------|
| READ | `read_file`, `query`, `list` | LOW |
| WRITE | `write_file`, `update`, `save` | MEDIUM |
| DELETE | `delete_file`, `remove`, `drop` | HIGH |
| EXECUTE | `shell`, `run_command`, `eval` | CRITICAL |
| NETWORK | `http_request`, `fetch`, `upload` | MEDIUM |
| FINANCIAL | `transfer`, `payment`, `purchase` | CRITICAL |
| COMMUNICATION | `send_email`, `post_social` | MEDIUM-HIGH |
| AUTHENTICATION | `login`, `change_password` | MEDIUM-HIGH |
| SYSTEM | `sudo`, `install`, `config` | HIGH-CRITICAL |

## Approval Workflow

### Requesting Approval

```python
result = authorizer.authorize("execute_shell", {"command": "ls -la"})

if result.requires_approval:
    action_id = result.action.id
    print(f"Approval needed: {action_id}")
    
    # Option 1: Wait for approval (blocking)
    status = authorizer.wait_for_approval(result.approval_request)
    
    # Option 2: Check status later (non-blocking)
    status = authorizer.check_approval_status(action_id)
```

### Approving/Denying

```python
# Approve
authorizer.approve(action_id, approved_by="admin@company.com")

# Deny
authorizer.deny(action_id, reason="Too risky", denied_by="admin@company.com")
```

### Getting Pending Approvals

```python
pending = authorizer.get_pending_approvals()

for request in pending:
    print(f"{request.action.name}: {request.action.description}")
    print(f"  Risk: {request.action.risk}")
    print(f"  Expires: {request.expires_at}")
```

## Configuration

### Custom Risk Thresholds

```python
from vibeguard.authorization import ActionAuthorizer, ActionRisk

authorizer = ActionAuthorizer(
    auto_approve_risk=ActionRisk.MEDIUM,     # Auto-approve up to MEDIUM
    require_approval_risk=ActionRisk.CRITICAL,  # Only require approval for CRITICAL
    auto_deny_risk=None,                     # Never auto-deny (or set to CRITICAL)
)
```

### Approval Timeout

```python
from datetime import timedelta

authorizer = ActionAuthorizer(
    approval_timeout=timedelta(minutes=10),  # Requests expire after 10 min
)
```

### Approval Callback

Get notified when approval is needed:

```python
def on_approval_needed(request):
    # Send Slack notification, email, etc.
    send_slack(f"Approval needed: {request.action.name}")

authorizer = ActionAuthorizer(
    approval_callback=on_approval_needed,
)
```

### Rate Limiting

```python
from datetime import timedelta
from vibeguard.authorization import ActionCategory

authorizer = ActionAuthorizer(
    rate_limits={
        ActionCategory.DELETE: (5, timedelta(hours=1)),    # 5 deletes per hour
        ActionCategory.FINANCIAL: (3, timedelta(hours=1)), # 3 payments per hour
        ActionCategory.COMMUNICATION: (10, timedelta(minutes=10)),  # 10 emails per 10 min
    }
)
```

### Audit Logging

```python
authorizer = ActionAuthorizer(
    audit_log="agent_actions.jsonl",
)

# All actions are logged with:
# - timestamp
# - action details
# - decision (approved/denied/pending)
# - who approved/denied
```

## Custom Classification

### Custom Rules

```python
from vibeguard.authorization import ActionClassifier, ActionCategory, ActionRisk

classifier = ActionClassifier(
    custom_rules={
        r"deploy_.*": (ActionCategory.SYSTEM, ActionRisk.CRITICAL),
        r"backup_.*": (ActionCategory.WRITE, ActionRisk.LOW),
        r"test_.*": (ActionCategory.READ, ActionRisk.LOW),
    }
)

authorizer = ActionAuthorizer(classifier=classifier)
```

## Integration with Guard

Use authorization alongside input/output scanning:

```python
from vibeguard import Guard
from vibeguard.authorization import ActionAuthorizer

guard = Guard(redact_pii=True)
authorizer = ActionAuthorizer()

def agent_action(action_name: str, params: dict, user_input: str):
    # 1. Check user input
    input_result = guard.check_input(user_input)
    if input_result.blocked:
        return f"Input blocked: {input_result.reason}"
    
    # 2. Authorize action
    auth_result = authorizer.authorize(action_name, params)
    if not auth_result.authorized:
        if auth_result.requires_approval:
            return f"Action pending approval: {auth_result.action.id}"
        return f"Action denied: {auth_result.reason}"
    
    # 3. Execute action
    result = execute_action(action_name, params)
    
    # 4. Check output
    output_result = guard.check_output(str(result))
    return output_result.sanitized_text
```

## Dashboard Integration

View and manage approvals in the web dashboard:

```python
from vibeguard.dashboard import run_dashboard
from vibeguard.authorization import ActionAuthorizer

authorizer = ActionAuthorizer(audit_log="actions.jsonl")

# Dashboard shows pending approvals
run_dashboard(
    port=8080,
    audit_log_path="actions.jsonl",
    authorizer=authorizer,
)
```
