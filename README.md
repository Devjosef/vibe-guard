# ██ Vibe-Guard Security Scanner

*Update March 2026*
The Linux/Arch binary packages are currently not working. I’ve taken them down, so please avoid downloading them.
For now, I recommend using the Windows or macOS releases instead. Any help, debugging, or suggestions are very welcome!

**Professional Security Scanner** - Zero dependencies, instant setup, works everywhere. Optimized performance for security scanning. Current ruleset: 28 essential security rules including container security.

[![npm version](https://img.shields.io/npm/v/vibe-guard.svg)](https://www.npmjs.com/package/vibe-guard)
[![Downloads (total)](https://img.shields.io/npm/dt/vibe-guard.svg)](https://www.npmjs.com/package/vibe-guard)
[![License](https://img.shields.io/npm/l/vibe-guard.svg)](https://github.com/Devjosef/vibe-guard/blob/main/LICENSE)


## Quick Start

```bash
# Install globally
npm install -g vibe-guard

# For Development with no build step(run this first)
npm run dev

# Start interactive session
vibe-guard start

# Scan your project
vibe-guard scan .

# Learn about security concepts
vibe-guard learn xss-detection

# Try with demo files
vibe-guard demo
```

## Interactive Security Learning

Vibe-Guard is more than a scanner, it is an educational platform that teaches you about web security through hands on experience

### Understanding Vulnerabilities

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
        image: nginx:1.21.6@sha256:abc123...  # Pinned digest
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

Vibe-Guard detects 28 types of vulnerabilities across multiple categories:

- **Authentication & Authorization**: Missing authentication, broken access control, session management
- **Input Validation**: SQL injection, XSS, unvalidated input, directory traversal
- **Data Protection**: Exposed secrets, hardcoded sensitive data, insecure logging
- **Configuration**: Insecure configuration, missing security headers, CORS issues
- **Modern Threats**: CSRF protection, AI-generated code validation, prompt injection
- **Dependencies**: Insecure dependencies, outdated packages, vulnerability assessment
- **Container Security**: Kubernetes security, Dockerfile vulnerabilities, container registry issues

## Professional Use Cases

**CI/CD Integration:**
```yaml
# GitHub Actions
- name: Security Scan
  run: vibe-guard scan . --format sarif --output-file security-report.sarif
```

## SARIF test reporting

This repository can produce SARIF from the Jest test suite for integration with GitHub Code Scanning.
Locally you can run:

```bash
# run tests and produce JSON
npx jest --json --outputFile=jest-output.json

# convert to SARIF
node scripts/jest-to-sarif.js jest-output.json test-results.sarif
```

The `jest-to-sarif` converter supports two optional flags: `--include-passed` (include passed/skipped assertions in SARIF) and `--relative-paths` (output relative file paths instead of file:// URIs). Example:

```bash
node scripts/jest-to-sarif.js jest-output.json test-results.sarif --include-passed --relative-paths
```

CI converts Jest JSON to SARIF and uploads the SARIF file when the tests are run in the CI workflow.

**Pre-commit Hook:**
```bash
# .git/hooks/pre-commit
#!/bin/sh
vibe-guard scan . || exit 1
```

**Interactive Learning:**
```bash
# Start interactive session
vibe-guard start

# Learn specific security concepts
vibe-guard learn sql-injection
vibe-guard learn xss-detection

# Practice with demo files
vibe-guard demo
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

**Direct Download:**
```bash

# macOS
curl -L https://github.com/Devjosef/vibe-guard/releases/latest/download/vibe-guard-macos-x64 -o vibe-guard
chmod +x vibe-guard

# Windows
curl -L https://github.com/Devjosef/vibe-guard/releases/latest/download/vibe-guard-windows-x64.exe -o vibe-guard.exe
```

## Documentation & Resources

- **[Getting Started](https://devjosef.github.io/vibe-guard/getting-started.html)** - Complete setup and configuration guide
- **[Security Rules](https://devjosef.github.io/vibe-guard/rules.html)** - Detailed rule explanations and examples
- **[Performance Guide](https://devjosef.github.io/vibe-guard/performance.html)** - Optimization and best practices
- **[API Reference](https://devjosef.github.io/vibe-guard/docs.html)** - Programmatic usage and integration

## Community & Support

**Join our community of security professionals and developers:**

- **Interactive Learning**: `vibe-guard start` - Begin your security journey
- **Educational Commands**: `vibe-guard learn [topic]` - Master security concepts
- **Hands-on Practice**: `vibe-guard demo` - Test with example vulnerabilities
- **Performance Insights**: `vibe-guard stats` - Track your security impact
- **Community Discussion**: [GitHub Discussions](https://github.com/Devjosef/vibe-guard/discussions)
- **Issue Reporting**: [GitHub Issues](https://github.com/Devjosef/vibe-guard/issues)
- **Repository**: [GitHub Repository](https://github.com/Devjosef/vibe-guard)

## Why Choose Vibe-Guard?

**Built for developers who code fast and need security that keeps up:**

- **Zero Dependencies** - Lightweight, fast, and reliable
- **28 Security Rules** - Comprehensive coverage of modern threats including container security
- **Cross-Platform** - Works seamlessly across all operating systems
- **Educational Focus** - Learn security while you scan
- **OWASP Aligned** - Industry best practices and standards
- **Developer-Friendly** - Simple, intuitive CLI interface
- **Interactive Mode** - Guided learning with `vibe-guard start`
- **Container Security** - Kubernetes, Dockerfile, and registry security scanning

## Impact & Adoption

Every scan contributes to a more secure web ecosystem:

- **500+ total downloads** on NPM with growing adoption
- **28 security rules** covering contemporary threat vectors including container security
- **Cross-platform support** for macOS, and Windows
- **Zero dependencies** ensuring maximum compatibility
- **Educational approach** - building security awareness
- **Container security** - Kubernetes, Dockerfile, and registry vulnerability detection

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built for the greater good, like curl for security scanning.** 
