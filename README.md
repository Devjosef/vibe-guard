# ██ Vibe-Guard Security Scanner

Vibe-Guard gives you a quick security pass over source code and configuration files, with 30 pattern-based rules covering common application, AI, dependency, and container risks. Findings include a suggested next step, so scans can also help you learn what to look for.

It is a heuristic scanner, not a substitute for code review or a full security audit. It requires Node.js 20 or newer; npm installs its declared third-party runtime dependencies for you.

[![npm version](https://img.shields.io/npm/v/vibe-guard.svg)](https://www.npmjs.com/package/vibe-guard)
[![Downloads (total)](https://img.shields.io/npm/dt/vibe-guard.svg)](https://www.npmjs.com/package/vibe-guard)
[![License](https://img.shields.io/npm/l/vibe-guard.svg)](https://github.com/Devjosef/vibe-guard/blob/main/LICENSE)


## Quick Start

```bash
# Install globally
npm install -g vibe-guard

# Interactive menu (scan and view rules)
vibe-guard start

# Scan your project
vibe-guard scan .

# Export a SARIF report
vibe-guard scan . --format sarif --output-file security-report.sarif
```

`vibe-guard scan` requires a target path. Supported formats are `table`, `json`, `sarif`, and `html`. A scan with findings exits with code 1; scan errors exit with code 2. The interactive `start` menu lets you scan, view the rule list, and create or view a configuration file. There are no separate `learn`, `demo`, or `stats` commands.

## Common issues and safer patterns

**XSS (Cross-Site Scripting):**
```javascript
// Vulnerable code
app.get('/user', (req, res) => {
  const userInput = req.query.name;
  res.send('<h1>Hello ' + userInput + '</h1>'); // XSS vulnerability!
});

// Secure code
app.get('/user', (req, res) => {
  const userInput = req.query.name;
  res.send('<h1>Hello ' + escapeHtml(userInput) + '</h1>');
});
```

**SQL Injection:**
```javascript
// Vulnerable code
const query = 'SELECT * FROM users WHERE id = ' + userId; // SQL injection risk!

// Secure code
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);
```

**Exposed Secrets:**
```javascript
// Vulnerable code
const API_KEY = 'sk-1234567890abcdef'; // Secret exposed in source code!

// Secure code
const API_KEY = process.env.API_KEY; // Environment variable
```

**Container Security:**
```yaml
# Vulnerable Kubernetes manifest
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest  # Latest tag vulnerability
        securityContext:
          runAsUser: 0       # Root user vulnerability
          privileged: true   # Privileged container vulnerability

# Secure Kubernetes manifest
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.21.6@sha256:<real-image-digest>  # Replace with the registry's actual digest
        securityContext:
          runAsUser: 1000    # Non-root user
          runAsNonRoot: true
          allowPrivilegeEscalation: false
```

### Security Best Practices

1. **Input Validation** - Always validate and sanitize user input
2. **Output Encoding** - Encode output to prevent XSS attacks
3. **Parameterized Queries** - Use prepared statements for database operations
4. **Environment Variables** - Never hardcode secrets in source code
5. **Security Headers** - Implement proper HTTP security headers

6. **Container Security** - Use non-root users, pinned image digests, and proper security contexts

## Comprehensive Security Coverage

Vibe-Guard detects 30 types of vulnerabilities across multiple categories:

- **Authentication & Authorization**: Missing authentication, broken access control, session management
- **Input Validation**: SQL injection, XSS, unvalidated input, directory traversal
- **Data Protection**: Exposed secrets, hardcoded sensitive data, insecure logging
- **Configuration**: Insecure configuration, missing security headers, CORS issues
- **Modern Threats**: AI provider tokens, unsafe LLM prompt construction, prompt injection, MCP security
- **Dependencies**: Known vulnerable packages, floating versions, and mutable Git references
- **Container Security**: Kubernetes security, Dockerfile vulnerabilities, container registry issues

## Use it in your workflow

**CI/CD Integration:**
```yaml
# GitHub Actions
- name: Security Scan
  run: vibe-guard scan . --format sarif --output-file security-report.sarif
```

## SARIF test reporting

For local Jest test-result reporting, see [TEST_SCANNING.md](docs/TEST_SCANNING.md); that utility is separate from scanning project code.

**Pre-commit Hook:**
```bash
# .git/hooks/pre-commit
#!/bin/sh
vibe-guard scan . || exit 1
```

**Interactive menu:**
```bash
vibe-guard start
```

## Installation Options

**NPM (Recommended):**
```bash
npm install -g vibe-guard
```

**Homebrew:**
```bash
brew install devjosef/tap/vibe-guard
```

Standalone binaries for Linux x64/arm64, macOS x64/arm64, and Windows x64 are built in CI and uploaded as workflow artifacts. They are not currently published as GitHub release downloads.

## Documentation & Resources

- **[Getting Started](https://devjosef.github.io/vibe-guard/getting-started.html)** - Complete setup and configuration guide
- **[Security Rules](https://devjosef.github.io/vibe-guard/features.html)** - Rule coverage and descriptions
- **[Performance Guide](https://devjosef.github.io/vibe-guard/performance.html)** - Optimization and best practices
- **[API Reference](https://devjosef.github.io/vibe-guard/docs.html)** - Programmatic usage and integration

## Community & Support

**Questions, feedback, or a finding that looks wrong?**

- **Interactive menu**: `vibe-guard start` - Scan or view available rules
- **SARIF export**: `vibe-guard scan . --format sarif --output-file report.sarif`
- **Community Discussion**: [GitHub Discussions](https://github.com/Devjosef/vibe-guard/discussions)
- **Issue Reporting**: [GitHub Issues](https://github.com/Devjosef/vibe-guard/issues)
- **Repository**: [GitHub Repository](https://github.com/Devjosef/vibe-guard)

## What to expect

- Findings include the rule, severity, file and line, explanation, and suggested remediation.
- Pattern-based checks can miss issues or flag safe code; review findings in context and do not treat a clean scan as proof that code is secure.
- `start` is a small interactive menu for scanning and browsing rule descriptions, not a guided course.
- CI runs the Jest suite on Node.js 20 and 22. Binary builds are CI artifacts until attached to a release.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built for the greater good, like curl for security scanning.** 
