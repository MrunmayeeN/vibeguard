# Contributing to VibeGuard

First off, thanks for taking the time to contribute! 🎉

## How Can I Contribute?

### Reporting Bugs

- Use the GitHub issue tracker
- Include Python version, OS, and vibeguard version
- Provide a minimal reproducible example
- Describe expected vs actual behavior

### Suggesting Features

- Open an issue with the "enhancement" label
- Explain the use case
- Describe the expected behavior

### Pull Requests

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Run linting (`ruff check .`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vibeguard.git
cd vibeguard

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
mypy src/vibeguard
```

## Code Style

- We use [ruff](https://github.com/astral-sh/ruff) for linting
- We use [mypy](https://mypy-lang.org/) for type checking
- Maximum line length is 100 characters
- Use type hints for all function signatures
- Write docstrings for all public functions/classes

## Adding a New Scanner

1. Create a new file in `src/vibeguard/scanners/`
2. Inherit from `Scanner` base class
3. Implement the `scan()` method
4. Add tests in `tests/`
5. Update documentation

Example:
```python
from vibeguard.scanners import Scanner
from vibeguard.models import Issue, IssueType, IssueSeverity, ScanDirection

class MyScanner(Scanner):
    name = "my_scanner"
    
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        issues = []
        # Your detection logic here
        return issues
```

## Security Vulnerabilities

If you discover a security vulnerability, please open a private security advisory on GitHub instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
