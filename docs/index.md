# VibeGuard Documentation

Welcome to VibeGuard - open-source AI security for vibe coders and AI companies.

## Table of Contents

- [Getting Started](getting-started.md)
- [Scanners](scanners.md)
- [Integrations](integrations.md)
- [Policy Engine](policies.md)
- [Agent Authorization](authorization.md)
- [Dashboard](dashboard.md)
- [API Reference](api-reference.md)

## Quick Links

- **GitHub**: https://github.com/MrunmayeeN/vibeguard
- **PyPI**: https://pypi.org/project/vibeguard/
- **Issues**: https://github.com/MrunmayeeN/vibeguard/issues

## Installation

```bash
pip install vibeguard
```

## Basic Usage

```python
from vibeguard import Guard

guard = Guard()
result = guard.check_input(user_message)

if result.blocked:
    print(f"Blocked: {result.reason}")
else:
    # Safe to send to LLM
    response = llm.generate(result.sanitized_text)
```

## Features

| Feature | Description |
|---------|-------------|
| Prompt Injection | Detects instruction overrides, jailbreaks, DAN attacks |
| PII Detection | Email, phone, SSN, credit cards with redaction |
| Secrets Scanning | 20+ patterns for API keys, tokens, passwords |
| Token Limits | Cost control with daily/per-request limits |
| MCP Security | Tool poisoning detection for AI agents |
| Toxicity | Hate speech, harassment, violence detection |
| Hallucination | Fabricated citations, statistics, dates |
| Authorization | Human-in-the-loop for risky agent actions |
