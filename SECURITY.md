# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Vibe-Guard seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to `devjosef@github.com`.

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:

- Type of issue (buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the vulnerability
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Policy

Vibe-Guard follows the principle of [Responsible Disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure).

## Security Best Practices

When using Vibe-Guard:

1. **Keep it updated**: Always use the latest version
2. **Review findings**: Don't blindly trust automated results
3. **Use in CI/CD**: Integrate into your development workflow
4. **Combine with other tools**: Use as part of a comprehensive security strategy
5. **Report false positives**: Help improve the tool's accuracy

## Security Features

Vibe-Guard itself is designed with security in mind:

- **Zero dependencies**: Reduces attack surface
- **Static analysis**: No code execution during scanning
- **Sandboxed**: Safe to run on any codebase
- **Transparent**: All rules and patterns are open source
- **Auditable**: Every detection can be traced to specific patterns

## Security Rules

Vibe-Guard detects 25 categories of security vulnerabilities:

### Critical (7 rules)
- Exposed secrets
- Hardcoded sensitive data  
- XSS detection
- SQL injection
- Directory traversal
- Insecure deserialization
- Broken access control

### High (12 rules)
- Missing authentication
- Open CORS
- CSRF protection
- Insecure file upload
- Insecure session management
- Insecure HTTP usage
- Insecure dependencies
- Missing security headers
- Insecure random generation
- Insecure logging
- Insecure error handling
- Insecure configuration

### Medium (6 rules)
- Unvalidated input
- AI-generated code validation
- AI data leakage prevention
- Prompt injection detection
- AI agent access control
- MCP server security

For detailed information about each rule, see our [Security Rules Documentation](https://devjosef.github.io/vibe-guard/rules.html). 