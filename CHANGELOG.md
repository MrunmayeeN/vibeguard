# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-27

### Added
- Initial release
- Core `Guard` class with input/output scanning
- **Scanners:**
  - Prompt injection detection (40+ patterns)
  - PII detection and redaction (email, phone, SSN, credit cards)
  - Secrets detection (OpenAI, Anthropic, AWS, GitHub, 20+ patterns)
  - Token counting and cost controls
  - MCP tool security scanning
  - Toxicity detection (hate speech, harassment, violence)
  - Hallucination detection (fabricated citations, statistics, dates)
- **Policy engine** with customizable rules and preset policies
- **Integrations:**
  - OpenAI (`GuardedOpenAI` drop-in replacement)
  - Anthropic (`GuardedAnthropic` drop-in replacement)
  - LangChain (`VibeGuardCallback`)
- **Agent action authorization** with approval workflows
- **Dashboard** for monitoring and management
- **CLI tool** (`vibeguard check`, `vibeguard scan`)
- YAML configuration support
- Audit logging (JSONL + webhook)

### Security
- Blocks prompt injection attempts
- Redacts PII before sending to LLMs
- Prevents secret/API key leakage
- Rate limiting for agent actions
