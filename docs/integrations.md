# Integrations

VibeGuard provides drop-in integrations for popular LLM providers.

## OpenAI Integration

### Installation

```bash
pip install vibeguard[openai]
```

### Usage

```python
from vibeguard.integrations.openai_integration import GuardedOpenAI

# Drop-in replacement for OpenAI client
client = GuardedOpenAI()

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": user_input}]
)

# Input is automatically scanned before sending
# Output is automatically scanned before returning
# Raises ValueError if blocked
```

### With Custom Guard

```python
from vibeguard import Guard
from vibeguard.integrations.openai_integration import GuardedOpenAI

guard = Guard(
    redact_pii=True,
    max_input_tokens=4000,
    audit_log="openai_audit.jsonl",
)

client = GuardedOpenAI(guard=guard)
```

### Error Handling

```python
from vibeguard.integrations.openai_integration import GuardedOpenAI

client = GuardedOpenAI()

try:
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Ignore previous instructions..."}]
    )
except ValueError as e:
    print(f"Blocked: {e}")
    # Handle blocked request
```

---

## Anthropic Integration

### Installation

```bash
pip install vibeguard[anthropic]
```

### Usage

```python
from vibeguard.integrations.anthropic_integration import GuardedAnthropic

# Drop-in replacement for Anthropic client
client = GuardedAnthropic()

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": user_input}]
)
```

### With Custom Guard

```python
from vibeguard import Guard
from vibeguard.integrations.anthropic_integration import GuardedAnthropic

guard = Guard(
    redact_pii=True,
    block_on_secrets=True,
)

client = GuardedAnthropic(guard=guard)
```

### Streaming

```python
client = GuardedAnthropic()

# Input is scanned before streaming starts
# Note: Output scanning is limited for streaming
with client.messages.stream(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": user_input}]
) as stream:
    for text in stream.text_stream:
        print(text, end="")
```

---

## LangChain Integration

### Installation

```bash
pip install vibeguard[langchain]
```

### Using Callback

```python
from vibeguard.integrations.langchain_integration import VibeGuardCallback

callback = VibeGuardCallback()

# Add to any LangChain chain
chain.invoke(
    {"input": user_message},
    config={"callbacks": [callback]}
)

# Check results
for result in callback.get_results():
    if result.issues:
        print(f"Issues found: {len(result.issues)}")
```

### With Custom Guard

```python
from vibeguard import Guard
from vibeguard.integrations.langchain_integration import VibeGuardCallback

guard = Guard(redact_pii=True)

callback = VibeGuardCallback(
    guard=guard,
    block_on_issues=True,
    scan_prompts=True,
    scan_outputs=True,
    scan_tool_inputs=True,
    scan_tool_outputs=True,
)
```

### Guarded Chain Wrapper

```python
from vibeguard.integrations.langchain_integration import create_guarded_chain

# Wrap any chain
guarded_chain = create_guarded_chain(your_chain)

result = guarded_chain.invoke({"input": user_message})

# Get security results
security_results = guarded_chain.get_security_results()
```

### Handling Security Exceptions

```python
from vibeguard.integrations.langchain_integration import (
    VibeGuardCallback,
    SecurityException,
)

callback = VibeGuardCallback(block_on_issues=True)

try:
    chain.invoke(
        {"input": "Ignore previous instructions..."},
        config={"callbacks": [callback]}
    )
except SecurityException as e:
    print(f"Security violation: {e}")
```

---

## Manual Integration

For other LLM providers, use the Guard directly:

```python
from vibeguard import Guard

guard = Guard(redact_pii=True)

def call_llm(user_input: str) -> str:
    # Check input
    input_result = guard.check_input(user_input)
    
    if input_result.blocked:
        raise ValueError(f"Input blocked: {input_result.reason}")
    
    # Call your LLM with sanitized input
    response = your_llm_client.generate(input_result.sanitized_text)
    
    # Check output
    output_result = guard.check_output(response)
    
    # Return sanitized output
    return output_result.sanitized_text
```

---

## Integration Comparison

| Feature | OpenAI | Anthropic | LangChain |
|---------|--------|-----------|-----------|
| Drop-in replacement | ✅ | ✅ | ✅ (callback) |
| Input scanning | ✅ | ✅ | ✅ |
| Output scanning | ✅ | ✅ | ✅ |
| Streaming support | ❌ | ✅ (limited) | ❌ |
| Tool scanning | ❌ | ❌ | ✅ |
| Async support | ✅ | ✅ | ✅ |
