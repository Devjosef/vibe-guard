# Vibe-Guard Security Scanner

**The security scanner that actually catches real vulnerabilities without the noise**

Zero dependencies • Instant setup • Works everywhere • 25 essential security rules

## What Is This Thing?

Vibe-Guard catches the security mistakes we all make when we're coding fast. You know the drill you're in the zone, AI is helping you code, or you're quickly prototyping something, and suddenly you've got API keys in your code or forgot to add auth to that admin endpoint. We've all been there.

### The Core Philosophy

- **Catch real issues** - Not theoretical vulnerabilities that don't matter
- **Zero false positives** - If it flags something, it's actually a problem
- **Fast enough to use daily** - Scans your entire project in seconds
- **Works everywhere** - macOS, Linux, Windows, Docker, CI/CD
- **No setup required** - Download and run, that's it

## Quick Start (The "Just Show Me Code" Section)

### Option 1: Download Binary (Recommended)
```bash
# macOS (Intel)
curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.1.3/vibe-guard-macos-x64 -o vibe-guard
chmod +x vibe-guard
./vibe-guard scan .

# macOS (Apple Silicon)
curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.1.3/vibe-guard-macos-arm64 -o vibe-guard
chmod +x vibe-guard
./vibe-guard scan .

# Linux
curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.1.3/vibe-guard-linux-x64 -o vibe-guard
chmod +x vibe-guard
./vibe-guard scan .
```

### Option 2: NPM
```bash
# One-time use
npx vibe-guard scan .

# Global install
npm install -g vibe-guard
vibe-guard scan .
```

### Option 3: Docker
```bash
docker run --rm -v $(pwd):/code vibe-guard/vibe-guard:1.1.3 scan /code
```

## The 25 Security Rules (What It Actually Catches)

### 🚨 Critical Issues (7 Rules)
These will get you hacked. Fix them immediately.

- **Exposed Secrets**: API keys, tokens, credentials in code
- **Hardcoded Sensitive Data**: Database passwords, JWT secrets, encryption keys  
- **XSS Detection**: Cross-site scripting vulnerabilities

### ⚠️ High-Risk Issues (12 Rules)
These are serious but won't immediately compromise your app.

- **Missing Authentication**: Unprotected admin routes and API endpoints
- **SQL Injection**: String concatenation in database queries
- **Directory Traversal**: Unsafe file path operations
- **Open CORS**: Wildcard origins that let anyone access your API
- **CSRF Protection**: Missing CSRF tokens in forms and unsafe cookies
- **Insecure Deserialization**: Unsafe JSON parsing and eval usage
- **Broken Access Control**: Missing authorization checks
- **Insecure File Upload**: Unsafe file handling and validation
- **Insecure Session Management**: Weak session secrets and insecure cookies

### 📋 Medium Issues (13 Rules)
These are security best practices that should be addressed.

- **Unvalidated Input**: Direct use of user input without checks
- **Insecure HTTP**: Using HTTP instead of HTTPS
- **Insecure Dependencies**: Outdated packages with known security issues
- **Missing Security Headers**: No helmet.js or manual security headers
- **Insecure Random Generation**: Using Math.random() for security purposes
- **Insecure Logging**: Sensitive data exposure in logs
- **Insecure Error Handling**: Stack trace and information disclosure
- **Insecure Configuration**: Debug mode and security features disabled
- **AI-Generated Code Validation**: Detecting potentially unsafe AI-generated code
- **AI Data Leakage Prevention**: Preventing sensitive data exposure in AI outputs
- **Prompt Injection Detection**: Detecting potential prompt injection vulnerabilities
- **AI Agent Access Control**: Ensuring proper access controls for AI agents
- **MCP Server Security**: Detecting insecure Model Context Protocol configurations

## Usage Examples

```bash
# Scan current directory (most common)
vibe-guard scan .

# Scan specific file
vibe-guard scan app.js

# JSON output for CI/CD
vibe-guard scan . --format json

# Quick syntax (same as scan)
vibe-guard .

# Show version
vibe-guard --version
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.1.3/vibe-guard-linux-x64 -o vibe-guard
    chmod +x vibe-guard
    ./vibe-guard scan .
```

### GitLab CI
```yaml
security_scan:
  script:
    - curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.1.3/vibe-guard-linux-x64 -o vibe-guard
    - chmod +x vibe-guard
    - ./vibe-guard scan .
```

### Docker in CI
```yaml
- name: Security Scan
  run: docker run --rm -v $(pwd):/code vibe-guard/vibe-guard:1.1.3 scan /code
```

## Scanner Sensitivity (How It Works)

Vibe-Guard is designed with **intelligent sensitivity** to balance detection accuracy with usability:

### Detection Characteristics
- **Detection Rate**: ~50-70% of potential issues (focused on real problems)
- **False Positive Rate**: Very low (designed for development workflows)
- **Performance**: Optimized scanning with streamlined detection patterns
- **Actionable Results**: Every issue includes specific fix suggestions

### Automatic Filtering
Vibe-Guard automatically filters out:
- Comments and documentation
- Test files and development code
- Environment variables (`${VAR}`, `process.env.VAR`)
- Safe patterns (parameterized queries, HTTPS, etc.)
- Framework-specific safeguards

### Use Cases
- **Development**: Current settings are well-balanced for daily use
- **Production Audits**: Consider running with verbose mode and manual review
- **Maximum Sensitivity**: Can be configured by modifying rule filters

## Language Support

Works with all the languages you actually use:
- **JavaScript/TypeScript**: .js, .jsx, .ts, .tsx
- **Python**: .py
- **PHP**: .php
- **Ruby**: .rb
- **Go**: .go
- **Java**: .java
- **C#**: .cs
- **Config files**: .json, .yaml, .yml, .env

## Development

Want to contribute or build from source?

```bash
# Clone and build
git clone https://github.com/Devjosef/vibe-guard.git
cd vibe-guard
npm install
npm run build

# Create binaries
npm run package

# Run tests
npm test
```

### Project Structure
```
src/
├── types/           # TypeScript definitions
├── rules/           # All 25 security rule implementations
├── bin/             # CLI interface
├── scanner.ts       # File scanning engine
├── reporter.ts      # Output formatting
└── index.ts         # Main application
```

## Why Choose Vibe-Guard?

### What You Get
- **Zero Setup**: Download and run, no dependencies
- **Fast Scanning**: Optimized patterns for speed
- **Real Issues**: Focused on actual vulnerabilities
- **Cross-Platform**: Works everywhere
- **CI/CD Ready**: Integrates seamlessly
- **Clear Fixes**: Every issue comes with specific solutions

### What You Don't Get
- Complex configuration files
- False positive spam
- Framework lock-in
- Slow scanning that kills your workflow
- Cryptic error messages

## Comparison

| Feature | Vibe-Guard | Other Tools |
|---------|------------|-------------|
| Setup Time | 0 seconds | Minutes |
| Dependencies | Zero | Many |
| False Positives | Minimal | High |
| Speed | ⚡ Fast | 🐌 Slow |
| Languages | All major ones | Limited |
| CI/CD Ready | ✅ Yes | ⚠️ Complex |
| Actually explains fixes | ✅ Yes | ❌ Cryptic |
| ARM64 Support | ✅ Yes | ❌ Limited |
| Security Rules | 25 comprehensive rules | Varies |

## Who This Is For

- **When you're coding with AI** - ChatGPT and Copilot are amazing, but they sometimes miss security basics
- **Rapid prototyping** - Building something quick? Don't let security be an afterthought
- **No-code/Low-code folks** - Generated code can have issues, this catches them
- **Your CI/CD pipeline** - Catch problems before they hit production
- **Code reviews** - Run this before you submit that PR
- **Learning security** - Get real-time feedback on what can or is going wrong (and how to fix it)

## Contributing

1. **Add Security Rules**: Extend the rule engine with new patterns
2. **Improve Detection**: Help reduce false positives
3. **Add Languages**: Support more file types and frameworks
4. **Better UX**: Improve CLI and output formatting

See [SECURITY_RULES.md](SECURITY_RULES.md) for detailed rule documentation.

## License

MIT License - Use it anywhere, anytime!

---

**Built with love by developers who got tired of slow, complex security tools.**

*Security shouldn't slow you down, but security holes definitely will.* 
