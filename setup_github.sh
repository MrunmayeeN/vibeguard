#!/bin/bash
# VibeGuard GitHub Setup Script
# Run this in the vibeguard folder after extracting the zip

echo "🛡️ VibeGuard GitHub Setup"
echo "========================="
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install git first."
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Please run this script from the vibeguard folder"
    echo "   cd vibeguard"
    echo "   ./setup_github.sh"
    exit 1
fi

echo "Step 1: Initializing git repository..."
git init

echo ""
echo "Step 2: Configuring git (if needed)..."
# Check if user.name is set
if [ -z "$(git config user.name)" ]; then
    echo "⚠️  Git user.name not set. Please run:"
    echo '   git config --global user.name "Your Name"'
    echo '   git config --global user.email "your.email@example.com"'
    echo ""
fi

echo "Step 3: Adding all files..."
git add .

echo ""
echo "Step 4: Creating initial commit..."
git commit -m "🚀 Initial release: VibeGuard v0.1.0

Features:
- Prompt injection detection with ML support
- PII detection and redaction
- Secrets scanning (20+ patterns)
- Token counting and limits
- MCP tool security scanning
- Toxicity detection
- Hallucination detection
- OpenAI, Anthropic, LangChain integrations
- Policy engine for custom rules
- Agent action authorization
- Web dashboard for monitoring
- CLI tool"

echo ""
echo "Step 5: Setting up main branch..."
git branch -M main

echo ""
echo "✅ Local repository ready!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "NEXT STEPS - Run these commands:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Connect to GitHub (replace YOUR_USERNAME with your GitHub username):"
echo ""
echo "   git remote add origin https://github.com/YOUR_USERNAME/vibeguard.git"
echo ""
echo "2. Push to GitHub:"
echo ""
echo "   git push -u origin main"
echo ""
echo "3. (Optional) Create a release tag:"
echo ""
echo "   git tag v0.1.0"
echo "   git push --tags"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
