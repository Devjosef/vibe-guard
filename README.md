#  Vibe-Guard Security Scanner

**Catches the security mistakes we all make when we code quickly**

Zero dependencies • Instant setup • Works everywhere • 10 essential security rules

##  Quick Start (Choose Your Style)

### Option 1: Download Binary Directly (Recommended)
```bash
# macOS (Intel)
curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.0.1/vibe-guard-macos-x64 -o vibe-guard
chmod +x vibe-guard
./vibe-guard scan .

# macOS (Apple Silicon)
curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.0.1/vibe-guard-macos-arm64 -o vibe-guard
chmod +x vibe-guard
./vibe-guard scan .

# Linux (x64)
curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.0.1/vibe-guard-linux-x64 -o vibe-guard
chmod +x vibe-guard
./vibe-guard scan .

# Linux (ARM64)
curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.0.1/vibe-guard-linux-arm64 -o vibe-guard
chmod +x vibe-guard
./vibe-guard scan .

# Windows
# Download vibe-guard-windows-x64.exe from releases page
```

### Option 2: Package Managers
```bash
# Homebrew (macOS/Linux) - Personal Tap
brew tap Devjosef/vibe-guard
brew install vibe-guard

# Chocolatey (Windows) - Ready for submission
# choco install vibe-guard

# RPM (RHEL/CentOS) - Ready for submission
# rpm -i https://github.com/Devjosef/vibe-guard/releases/latest/download/vibe-guard.rpm

# DEB (Ubuntu/Debian) - Ready for submission
# curl -L https://github.com/Devjosef/vibe-guard/releases/latest/download/vibe-guard.deb -o vibe-guard.deb
# sudo dpkg -i vibe-guard.deb
```

### Option 3: Docker (for CI/CD)
```bash
# Pull the latest image
docker pull vibe-guard/vibe-guard:latest

# Scan current directory
docker run --rm -v $(pwd):/code vibe-guard/vibe-guard:latest scan /code

# Scan specific file
docker run --rm -v $(pwd):/code vibe-guard/vibe-guard:latest scan /code/app.js

# Use specific version
docker run --rm -v $(pwd):/code vibe-guard/vibe-guard:1.0.1 scan /code
```

### Option 4: NPM (for Node.js users)
```bash
# Latest version (1.0.1)
npx vibe-guard scan .
# or
npm install -g vibe-guard
vibe-guard scan .
```

##  Why You'll Actually Use This

- **Zero Setup**: Download and run, no Node.js or dependencies required
- **Fast Enough to Not Be Annoying**: Scans your entire project in seconds
- **Won't Spam You**: Smart enough to know test code from real issues
- **Made by Developers**: We know what actually breaks in production
- **Works Everywhere**: macOS, Linux, Windows, Docker, CI/CD - you name it
- **ARM64 Support**: Native support for Apple Silicon and ARM64 Linux
- **Cross-Platform**: Single binary for each platform, no dependencies

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
    curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.0.1/vibe-guard-linux-x64 -o vibe-guard
    chmod +x vibe-guard
    ./vibe-guard scan .
```

### GitLab CI
```yaml
security_scan:
  script:
    - curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.0.1/vibe-guard-linux-x64 -o vibe-guard
    - chmod +x vibe-guard
    - ./vibe-guard scan .
```

### Docker in CI
```yaml
- name: Security Scan
  run: docker run --rm -v $(pwd):/code vibe-guard/vibe-guard:1.0.1 scan /code
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
| ARM64 Support | ✅ Yes | ❌ Limited |

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
