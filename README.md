#  Vibe-Guard Security Scanner

**Catches the security mistakes we all make when we code quickly**

Zero dependencies • Instant setup • Works everywhere • 10 essential security rules

##  Quick Start (Choose Your Style)

### Option 1: One-Line Install (Recommended)
```bash
# macOS/Linux - installs to /usr/local/bin
curl -L https://get-vibe-guard.sh | bash

# Then use anywhere:
vibe-guard scan .
```

### Option 2: Download Binary Directly
```bash
# macOS
curl -L https://github.com/user/vibe-guard/releases/latest/download/vibe-guard-macos -o vibe-guard
chmod +x vibe-guard
./vibe-guard scan .

# Linux
curl -L https://github.com/user/vibe-guard/releases/latest/download/vibe-guard-linux -o vibe-guard
chmod +x vibe-guard
./vibe-guard scan .

# Windows
# Download vibe-guard-win.exe from releases page
```

### Option 3: NPM (for Node.js users)
```bash
npx vibe-guard scan .
# or
npm install -g vibe-guard
vibe-guard scan .
```

### Option 4: Docker (for CI/CD)
```bash
# Scan current directory
docker run --rm -v $(pwd):/code vibe-guard scan /code

# Scan specific file
docker run --rm -v $(pwd):/code vibe-guard scan /code/app.js
```

##  Why You'll Actually Use This

- **Zero Setup**: Download and run, no Node.js or dependencies required
- **Fast Enough to Not Be Annoying**: Scans your entire project in seconds
- **Won't Spam You**: Smart enough to know test code from real issues
- **Made by Developers**: We know what actually breaks in production
- **Works Everywhere**: macOS, Linux, Windows, Docker, CI/CD - you name it

##  What It Catches (All 10 Rules)

### 🚨 Critical Issues (The Bad)
- **Exposed API Keys**: AWS, GitHub, Google, Slack, Stripe tokens in your code
- **Hardcoded Secrets**: Database passwords, JWT secrets, encryption keys
- **Database URLs**: MongoDB, PostgreSQL connection strings with credentials

### ⚠️ High-Risk Issues (The Ugly)
- **Missing Authentication**: Unprotected admin routes and API endpoints
- **SQL Injection**: String concatenation in database queries
- **Directory Traversal**: Unsafe file path operations
- **Open CORS**: Wildcard origins that let anyone access your API

### 📋 Medium Issues (The not so Good)
- **Unvalidated Input**: Direct use of user input without checks
- **Insecure HTTP**: Using HTTP instead of HTTPS
- **Vulnerable Dependencies**: Outdated packages with known security issues
- **Missing Security Headers**: No helmet.js or manual security headers

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

## 🔧 CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    curl -L https://get-vibe-guard.sh | bash
    vibe-guard scan .
```

### GitLab CI
```yaml
security_scan:
  script:
    - curl -L https://get-vibe-guard.sh | bash
    - vibe-guard scan .
```

### Docker in CI
```yaml
- name: Security Scan
  run: docker run --rm -v $(pwd):/code vibe-guard scan /code
```

## Who This Is For

- **When you're coding with AI** - ChatGPT and Copilot are amazing, but they sometimes miss security basics
- **Rapid prototyping** - Building something quick? Don't let security be an afterthought
- **No-code/Low-code folks** - Generated code can have issues, this catches them
- **Your CI/CD pipeline** - Catch problems before they hit production
- **Code reviews** - Run this before you submit that PR
- **Learning security** - Get real-time feedback on what can or is going wrong (and how to fix it)

## 🌍 Language Support

Works with all the languages you actually use:
- **JavaScript/TypeScript**: .js, .jsx, .ts, .tsx
- **Python**: .py
- **PHP**: .php
- **Ruby**: .rb
- **Go**: .go
- **Java**: .java
- **C#**: .cs
- **Config files**: .json, .yaml, .yml, .env

## 🏗️ Development

Want to contribute or build from source?

```bash
# Clone and build
git clone https://github.com/user/vibe-guard.git
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
├── rules/           # All 10 security rule implementations
├── bin/             # CLI interface
├── scanner.ts       # File scanning engine
├── reporter.ts      # Output formatting
└── index.ts         # Main application
```

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

## 🤝 Contributing

1. **Add Security Rules**: Extend the rule engine with new patterns
2. **Improve Detection**: Help reduce false positives
3. **Add Languages**: Support more file types and frameworks
4. **Better UX**: Improve CLI and output formatting (opportunity for VIM here for enthusiasts)

See [SECURITY_RULES.md](SECURITY_RULES.md) for detailed rule documentation.

## 📄 License

MIT License - Use it anywhere, anytime!

---

**Built with ❤️ by developers who got tired of slow, and complex security tools.**

*Security shouldn't slow you down, but security holes definitely will.* 
