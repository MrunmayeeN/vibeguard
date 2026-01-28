# Dashboard

VibeGuard includes a web dashboard for monitoring and managing security events.

## Installation

```bash
pip install vibeguard[dashboard]
```

## Quick Start

```python
from vibeguard.dashboard import run_dashboard

run_dashboard(port=8080)
# Open http://localhost:8080
```

## With Audit Log

```python
from vibeguard import Guard
from vibeguard.dashboard import run_dashboard

# Create guard with audit logging
guard = Guard(audit_log="audit.jsonl")

# Use guard in your app...
guard.check_input("user message")

# Run dashboard pointing to audit log
run_dashboard(
    port=8080,
    audit_log_path="audit.jsonl",
)
```

## Features

### Real-Time Stats

The dashboard shows:

- **Total Requests**: All scanned inputs/outputs
- **Blocked**: Requests that were blocked
- **Issues Detected**: Total security issues found
- **Pending Approvals**: Actions awaiting human approval

### Traffic Charts

24-hour visualization of:
- Request volume over time
- Blocked requests over time

### Issues Breakdown

Pie chart showing issues by type:
- Prompt injection
- PII detected
- Secrets detected
- etc.

### Recent Events

Live table of recent security events with:
- Timestamp
- Direction (input/output)
- Status (allowed/blocked)
- Issue count

### Approval Management

If using the authorization system:
- View pending approvals
- Approve or deny actions
- See approval history

## Configuration

### Full Options

```python
from vibeguard.dashboard import run_dashboard
from vibeguard.authorization import ActionAuthorizer

authorizer = ActionAuthorizer(audit_log="actions.jsonl")

run_dashboard(
    host="0.0.0.0",        # Bind address (default: 127.0.0.1)
    port=8080,              # Port (default: 8080)
    audit_log_path="audit.jsonl",  # Path to audit log
    authorizer=authorizer,  # For approval management
    debug=False,            # Flask debug mode
)
```

### Integration with Flask

```python
from flask import Flask
from vibeguard.dashboard import create_app

# Create dashboard app
dashboard = create_app(audit_log_path="audit.jsonl")

# Mount at /dashboard in your existing app
app = Flask(__name__)

@app.route("/")
def index():
    return "My App"

# Register dashboard blueprint
app.register_blueprint(dashboard, url_prefix="/dashboard")
```

## API Endpoints

The dashboard exposes these API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML |
| `/api/stats` | GET | Current statistics |
| `/api/events` | GET | Recent events |
| `/api/approvals` | GET | Pending approvals |
| `/api/approvals/<id>/approve` | POST | Approve action |
| `/api/approvals/<id>/deny` | POST | Deny action |

### Using the API

```python
import requests

# Get stats
stats = requests.get("http://localhost:8080/api/stats").json()
print(f"Total requests: {stats['total_requests']}")
print(f"Blocked: {stats['blocked_requests']}")

# Get recent events
events = requests.get("http://localhost:8080/api/events?limit=10").json()
for event in events:
    print(f"{event['timestamp']}: {event['blocked']}")

# Approve an action
requests.post(
    "http://localhost:8080/api/approvals/abc123/approve",
    json={"approved_by": "admin@company.com"}
)
```

## Security Considerations

⚠️ **Important**: The dashboard has no built-in authentication.

For production:

1. **Run behind a reverse proxy** (nginx, Caddy)
2. **Add authentication** (HTTP Basic Auth, OAuth)
3. **Restrict network access** (firewall, VPN)
4. **Use HTTPS**

Example nginx config:

```nginx
server {
    listen 443 ssl;
    server_name dashboard.yourcompany.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    auth_basic "VibeGuard Dashboard";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

## Custom Data Collector

For custom integrations, use the data collector directly:

```python
from vibeguard.dashboard import DashboardDataCollector

collector = DashboardDataCollector(
    audit_log_path="audit.jsonl",
    max_recent_events=100,
)

# Record events manually
collector.record_event({
    "timestamp": "2025-01-27T12:00:00Z",
    "blocked": False,
    "issues": [],
    "direction": "input",
})

# Get stats
stats = collector.get_stats()
print(f"Total: {stats.total_requests}")
print(f"By type: {stats.issues_by_type}")
```
