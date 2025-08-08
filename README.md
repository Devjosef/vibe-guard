# 🛡️ Vibe-Guard Security Scanner

**25 essential security rules to catch vulnerabilities before they catch you!** Zero dependencies, instant setup, works everywhere, optimized performance. Detects SQL injection, XSS, exposed secrets, CSRF, CORS issues, and more.

[![npm version](https://img.shields.io/npm/v/vibe-guard.svg)](https://www.npmjs.com/package/vibe-guard)
[![Downloads](https://img.shields.io/npm/dm/vibe-guard.svg)](https://www.npmjs.com/package/vibe-guard)
[![License](https://img.shields.io/npm/l/vibe-guard.svg)](https://github.com/Devjosef/vibe-guard/blob/main/LICENSE)

## 🚀 Quick Start

```bash
# Install globally
npm install -g vibe-guard

# Scan your project
vibe-guard scan .

# Learn about security concepts
vibe-guard learn xss-detection

# Try with demo files
vibe-guard demo
```

## 📚 Learning Security (Like curl teaches HTTP)

Vibe-Guard is more than a scanner - it's an educational tool that teaches you about web security:

### **Understanding Vulnerabilities**

**XSS (Cross-Site Scripting):**
```javascript
// ❌ Vulnerable code
app.get('/user', (req, res) => {
  const userInput = req.query.name;
  res.send('<h1>Hello ' + userInput + '</h1>'); // XSS!
});

// ✅ Secure code
app.get('/user', (req, res) => {
  const userInput = req.query.name;
  res.send('<h1>Hello ' + escapeHtml(userInput) + '</h1>');
});
```

**SQL Injection:**
```javascript
// ❌ Vulnerable code
const query = 'SELECT * FROM users WHERE id = ' + userId; // SQL injection!

// ✅ Secure code
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);
```

**Exposed Secrets:**
```javascript
// ❌ Vulnerable code
const API_KEY = 'sk-1234567890abcdef'; // Exposed in code!

// ✅ Secure code
const API_KEY = process.env.API_KEY; // Environment variable
```

### **Security Best Practices**

1. **Input Validation** - Always validate and sanitize user input
2. **Output Encoding** - Encode output to prevent XSS
3. **Parameterized Queries** - Use prepared statements for SQL
4. **Environment Variables** - Never hardcode secrets
5. **Security Headers** - Implement proper HTTP security headers

## 🛡️ Security Rules

Vibe-Guard detects 25 types of vulnerabilities:

- **Authentication & Authorization**: Missing authentication, broken access control
- **Input Validation**: SQL injection, XSS, unvalidated input
- **Data Protection**: Exposed secrets, hardcoded sensitive data
- **Configuration**: Insecure configuration, missing security headers
- **Session Management**: Insecure session handling
- **Error Handling**: Information disclosure through errors
- **File Operations**: Directory traversal, insecure file uploads
- **Dependencies**: Insecure dependencies, outdated packages
- **AI/ML Security**: AI-generated code validation, prompt injection
- **Modern Threats**: CSRF, CORS issues, insecure logging

## 🎯 Use Cases

**CI/CD Integration:**
```yaml
# GitHub Actions
- name: Security Scan
  run: vibe-guard scan . --format sarif --output-file security-report.sarif
```

**Pre-commit Hook:**
```bash
# .git/hooks/pre-commit
#!/bin/sh
vibe-guard scan . || exit 1
```

**Educational Tool:**
```bash
# Learn about security concepts
vibe-guard learn sql-injection
vibe-guard learn xss-detection

# Practice with demo files
vibe-guard demo
```

## 🌍 Installation

**NPM:**
```bash
npm install -g vibe-guard
```

**Homebrew:**
```bash
brew install devjosef/tap/vibe-guard
```

**Direct Download:**
```bash
# Linux
curl -L https://github.com/Devjosef/vibe-guard/releases/latest/download/vibe-guard-linux-x64 -o vibe-guard
chmod +x vibe-guard

# macOS
curl -L https://github.com/Devjosef/vibe-guard/releases/latest/download/vibe-guard-macos-x64 -o vibe-guard
chmod +x vibe-guard

# Windows
curl -L https://github.com/Devjosef/vibe-guard/releases/latest/download/vibe-guard-windows-x64.exe -o vibe-guard.exe
```

## 📖 Documentation

- **[Getting Started](https://devjosef.github.io/vibe-guard/getting-started.html)** - Complete setup guide
- **[Security Rules](https://devjosef.github.io/vibe-guard/rules.html)** - Detailed rule explanations
- **[Performance Guide](https://devjosef.github.io/vibe-guard/performance.html)** - Optimization tips
- **[API Reference](https://devjosef.github.io/vibe-guard/docs.html)** - Programmatic usage

## 🤝 Community

**Join us in making the web more secure:**

- 📚 **Learn**: `vibe-guard learn [topic]` - Understand security concepts
- 🎯 **Demo**: `vibe-guard demo` - Try with example vulnerabilities
- 📊 **Stats**: `vibe-guard stats` - See your security impact
- 💬 **Discuss**: [GitHub Discussions](https://github.com/Devjosef/vibe-guard/discussions)
- 🐛 **Report**: [GitHub Issues](https://github.com/Devjosef/vibe-guard/issues)
- 🌟 **Star**: [GitHub Repository](https://github.com/Devjosef/vibe-guard)

## 🚀 Why Vibe-Guard?

**Built for developers who code fast and need security that keeps up:**

- ⚡ **Zero dependencies** - Lightweight and fast
- 🎯 **25 security rules** - Comprehensive coverage
- 🌍 **Cross-platform** - Works everywhere
- 📚 **Educational** - Learn while you scan
- 🛡️ **OWASP aligned** - Industry best practices
- 🔧 **Developer-friendly** - Simple CLI interface

## 📈 Impact

Every scan makes the web a little more secure:

- **600+ downloads** on NPM
- **25 security rules** covering modern threats
- **Cross-platform** support (Linux, macOS, Windows)
- **Zero dependencies** for maximum compatibility
- **Educational focus** - teaching security concepts

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built for the greater good, like curl for security scanning.** 🛡️🚀 
