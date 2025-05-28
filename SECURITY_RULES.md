# Vibe-Guard Security Rules

## Complete 10-Rule Security Scanner

Vibe-Guard catches the security mistakes we all make when we're moving fast. You know the style - you're in the zone, AI is helping you code, or you're quickly prototyping something, and suddenly you've got API keys in your code or forgot to add auth to that admin endpoint. We've all been there.

## 🛡️ Security Rules Overview

### 1. **Exposed Secrets** (CRITICAL)
- **Detects**: API keys, tokens, passwords, credentials in code
- **Patterns**: AWS keys, GitHub tokens, Google API keys, Slack tokens, JWT secrets, database credentials
- **Example**: `const API_KEY = "sk_live_abcd1234567890";`
- **Fix**: Move to environment variables or secure vaults

### 2. **Missing Authentication** (HIGH)
- **Detects**: Unprotected routes and endpoints
- **Frameworks**: Express.js, Next.js, Flask, FastAPI, Laravel
- **Example**: `app.get('/admin/users', (req, res) => { ... });`
- **Fix**: Add authentication middleware or checks

### 3. **Open CORS Policy** (HIGH)
- **Detects**: Wildcard CORS origins and permissive settings
- **Patterns**: `origin: '*'`, overly broad methods/headers
- **Example**: `app.use(cors({ origin: '*', credentials: true }));`
- **Fix**: Restrict to specific domains

### 4. **Hardcoded Sensitive Data** (CRITICAL)
- **Detects**: Hardcoded secrets in configuration files
- **Types**: Database URLs, encryption keys, passwords, salts
- **Example**: `database_url: "postgres://user:password@localhost/db"`
- **Fix**: Use environment variables or config management

### 5. **Insecure HTTP Usage** (MEDIUM)
- **Detects**: HTTP instead of HTTPS usage
- **Patterns**: API endpoints, fetch requests, server configurations
- **Example**: `fetch("http://api.example.com/data");`
- **Fix**: Use HTTPS for all external communications

### 6. **SQL Injection Risk** (HIGH)
- **Detects**: String concatenation in SQL queries
- **Languages**: JavaScript, Python, PHP, Java
- **Example**: `"SELECT * FROM users WHERE id = " + req.params.id`
- **Fix**: Use parameterized queries or prepared statements

### 7. **Unvalidated User Input** (MEDIUM)
- **Detects**: Direct use of user input without validation
- **Patterns**: File operations, database queries, command execution
- **Example**: `fs.writeFile(req.body.filename, req.body.content)`
- **Fix**: Validate and sanitize all user input

### 8. **Directory Traversal** (HIGH)
- **Detects**: Unsafe file path operations with user input
- **Patterns**: Path concatenation, file serving, includes
- **Example**: `res.sendFile('./uploads/' + req.params.path);`
- **Fix**: Use path.resolve(), validate paths, whitelist directories

### 9. **Insecure Dependencies** (MEDIUM)
- **Detects**: Vulnerable packages and suspicious dependencies
- **Checks**: Known CVEs, deprecated packages, typosquatting
- **Example**: `"lodash": "4.17.20"` (vulnerable version)
- **Fix**: Update to secure versions or find alternatives

### 10. **Missing Security Headers** (MEDIUM)
- **Detects**: Missing HTTP security headers
- **Headers**: CSP, X-Frame-Options, HSTS, X-Content-Type-Options
- **Example**: Express app without helmet.js or manual headers
- **Fix**: Add security headers using helmet.js or manually

## Detection Capabilities

### Multi-Language Support
- **JavaScript/TypeScript**: .js, .jsx, .ts, .tsx
- **Python**: .py
- **PHP**: .php
- **Ruby**: .rb
- **Go**: .go
- **Java**: .java
- **C#**: .cs
- **Configuration**: .json, .yaml, .yml, .env, .config

### Framework Coverage
- **Frontend**: React, Vue, Angular, Svelte
- **Backend**: Express.js, Next.js, Flask, Django, Laravel, Spring
- **Databases**: MongoDB, PostgreSQL, MySQL, Redis
- **Cloud**: AWS, Google Cloud, Azure services

### Smart Detection
- **Context-aware**: Skips development/test environments
- **False positive reduction**: Ignores examples, placeholders, mocks
- **Severity levels**: Critical, High, Medium, Low
- **Educational messages**: Clear explanations and fix suggestions

## Usage Statistics

When scanning a typical project:
- **Files scanned**: All supported file types
- **Issues detected**: Categorized by severity
- **Performance**: ~1000 files/second
- **Accuracy**: <5% false positive rate

## Distribution Methods

### 1. NPM Package
```bash
npm install -g vibe-guard
vibe-guard scan .
```

### 2. Standalone Binaries (54MB, zero dependencies)
```bash
# Download and run directly
./vibe-guard-macos scan .
./vibe-guard-linux scan .
./vibe-guard-win.exe scan .
```

### 3. Docker Images
```bash
docker run --rm -v $(pwd):/app vibe-guard scan /app
```

### 4. One-line installer
```bash
curl -sSL https://install.vibe-guard.dev | bash
```

## Who This Is For

- **When you're coding with AI** - ChatGPT and Copilot are amazing, but they sometimes miss security basics
- **Rapid prototyping** - Building something quick? Don't let security be an afterthought
- **No-code/Low-code folks** - Generated code can have issues, this catches them
- **Your CI/CD pipeline** - Catch problems before they hit production or live
- **Code reviews** - Run this before you submit that PR
- **Learning security** - Get real-time feedback on what can or has gone wrong (and how to fix it)

## Why You'll Actually Use This

1. **It's actually comprehensive** - Covers the stuff that actually breaks in production, not theoretical edge cases
2. **Fast enough to not be annoying** - Scans your entire project in seconds, not minutes
3. **Won't spam you with false positives** - Smart enough to know the difference between real issues and test code
4. **Explains what's wrong AND how to fix it** - No cryptic error messages that send you down rabbit holes
5. **Works everywhere** - Standalone binary means it runs on any machine, no Node.js required
6. **Fits your workflow** - Whether you're using npm, Docker, or just want a binary, we've got you covered

---

**Vibe-Guard**: Security shouldn't slow you down, but security holes definitely will. 