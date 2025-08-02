# Vibe-Guard Security Rules

## Complete 25-Rule Security Scanner

Vibe-Guard catches the security mistakes we all make when we're moving fast. You know the style - you're in the zone, AI is helping you code, or you're quickly prototyping something, and suddenly you've got API keys in your code or forgot to add auth to that admin endpoint. We've all been there.

**Latest Update**: Performance optimizations and code quality improvements - streamlined detection patterns for faster scanning while maintaining accuracy.

## 🛡️ Security Rules Overview

### Critical Issues (7 Rules)
These will get you hacked. Fix them immediately.

### High-Risk Issues (12 Rules)  
These are serious but won't immediately compromise your app.

### Medium Issues (13 Rules)
These are security best practices that should be addressed.

## Critical Issues

### 1. Exposed Secrets (CRITICAL)
**What it catches**: API keys, tokens, passwords, credentials in code
**Why it matters**: These get you hacked immediately

```typescript
// ❌ Bad - Will be flagged
const API_KEY = "sk_live_abcd1234567890";
const token = "ghp_1234567890abcdef";
const password = "super_secret_password";

// ✅ Good - Won't be flagged
const API_KEY = process.env.API_KEY;
const token = process.env.GITHUB_TOKEN;
const password = process.env.DB_PASSWORD;
```

**Patterns detected**:
- AWS keys: `AKIA...`, `sk_live_...`
- GitHub tokens: `ghp_...`, `gho_...`
- Google API keys: `AIza...`
- Slack tokens: `xoxb-...`, `xoxp-...`
- JWT secrets: `eyJ...` (JWT format)
- Database credentials: `mongodb://user:pass@...`

**Fix**: Move to environment variables or secure vaults

### 2. Hardcoded Sensitive Data (CRITICAL)
**What it catches**: Hardcoded secrets in configuration files
**Why it matters**: Configuration files often get committed to version control

```yaml
# ❌ Bad - Will be flagged
database_url: "postgres://user:password@localhost/db"
encryption_key: "super_secret_key_123"
jwt_secret: "my_jwt_secret_key"

# ✅ Good - Won't be flagged
database_url: "${DATABASE_URL}"
encryption_key: "${ENCRYPTION_KEY}"
jwt_secret: "${JWT_SECRET}"
```

**Patterns detected**:
- Database URLs with credentials
- Encryption keys and salts
- JWT secrets
- API endpoints with embedded tokens

**Fix**: Use environment variables or configuration management

### 3. XSS Detection (CRITICAL)
**What it catches**: Cross-site scripting vulnerabilities
**Why it matters**: Allows attackers to execute malicious code in users' browsers

```javascript
// ❌ Bad - Will be flagged
element.innerHTML = req.body.userInput;
document.write(userData);
eval(userProvidedCode);

// ✅ Good - Won't be flagged
element.textContent = req.body.userInput;
element.appendChild(document.createTextNode(userData));
// Don't use eval with user input
```

**Patterns detected**:
- Unsafe DOM manipulation: `innerHTML`, `outerHTML`, `document.write`
- Eval with user input: `eval(userData)`
- Template injection: `${userInput}` in templates
- Event handlers with user input: `onclick="${userData}"`

**Fix**: Use `textContent`, sanitize input, or use DOMPurify

## High-Risk Issues

### 4. Missing Authentication (HIGH)
**What it catches**: Unprotected routes and endpoints
**Why it matters**: Anyone can access sensitive functionality

```javascript
// ❌ Bad - Will be flagged
app.get('/admin/users', (req, res) => {
  // No auth check
  res.json(users);
});

app.post('/api/sensitive-data', (req, res) => {
  // No auth check
  res.json(data);
});

// ✅ Good - Won't be flagged
app.get('/admin/users', authMiddleware, (req, res) => {
  res.json(users);
});

app.post('/api/sensitive-data', authenticate, (req, res) => {
  res.json(data);
});
```

**Patterns detected**:
- Express routes without auth middleware
- API endpoints without authentication
- Admin routes without protection
- Sensitive operations without checks

**Fix**: Add authentication middleware or checks

### 5. SQL Injection (HIGH)
**What it catches**: String concatenation in SQL queries
**Why it matters**: Allows database manipulation and data theft

```javascript
// ❌ Bad - Will be flagged
const query = "SELECT * FROM users WHERE id = " + req.params.id;
const result = await db.query(query);

const userQuery = `SELECT * FROM users WHERE name = '${req.body.name}'`;
const user = await db.query(userQuery);

// ✅ Good - Won't be flagged
const query = "SELECT * FROM users WHERE id = ?";
const result = await db.query(query, [req.params.id]);

const userQuery = "SELECT * FROM users WHERE name = ?";
const user = await db.query(userQuery, [req.body.name]);
```

**Patterns detected**:
- String concatenation in SQL: `"SELECT * FROM " + table`
- Template literals with user input: `` `SELECT * FROM users WHERE id = ${id}` ``
- Dynamic SQL construction without parameters

**Fix**: Use parameterized queries or prepared statements

### 6. Directory Traversal (HIGH)
**What it catches**: Unsafe file path operations with user input
**Why it matters**: Allows access to files outside intended directories

```javascript
// ❌ Bad - Will be flagged
const filePath = './uploads/' + req.params.filename;
res.sendFile(filePath);

const content = fs.readFileSync(req.query.path);

// ✅ Good - Won't be flagged
const filePath = path.join('./uploads', req.params.filename);
const safePath = path.resolve('./uploads', req.params.filename);
res.sendFile(safePath);

const safePath = path.resolve('./data', req.query.path);
const content = fs.readFileSync(safePath);
```

**Patterns detected**:
- Path concatenation with user input
- File operations without path validation
- Directory traversal attempts: `../../../etc/passwd`

**Fix**: Use `path.resolve()`, validate paths, whitelist directories

### 7. Open CORS (HIGH)
**What it catches**: Wildcard CORS origins and permissive settings
**Why it matters**: Allows any website to make requests to your API

```javascript
// ❌ Bad - Will be flagged
app.use(cors({
  origin: '*',
  credentials: true
}));

app.use(cors({
  origin: 'https://*',
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

// ✅ Good - Won't be flagged
app.use(cors({
  origin: ['https://myapp.com', 'https://admin.myapp.com'],
  credentials: true
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(','),
  methods: ['GET', 'POST']
}));
```

**Patterns detected**:
- Wildcard origins: `'*'`, `'https://*'`
- Overly permissive methods and headers
- Credentials with wildcard origins

**Fix**: Restrict to specific domains

### 8. CSRF Protection (HIGH)
**What it catches**: Missing CSRF tokens and unsafe cookie configurations
**Why it matters**: Allows unauthorized actions on behalf of users

```html
<!-- ❌ Bad - Will be flagged -->
<form method="post" action="/api/transfer">
  <input type="text" name="amount" />
  <button type="submit">Transfer</button>
</form>

<!-- ✅ Good - Won't be flagged -->
<form method="post" action="/api/transfer">
  <input type="hidden" name="_csrf" value="{{csrfToken}}" />
  <input type="text" name="amount" />
  <button type="submit">Transfer</button>
</form>
```

```javascript
// ❌ Bad - Will be flagged
app.use(session({
  secret: 'keyboard cat',
  cookie: { secure: false, httpOnly: false }
}));

// ✅ Good - Won't be flagged
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { 
    secure: true, 
    httpOnly: true, 
    sameSite: 'strict' 
  }
}));
```

**Patterns detected**:
- Forms without CSRF tokens
- Unsafe cookie configurations
- Missing CSRF middleware

**Fix**: Add CSRF tokens and configure secure cookies

### 9. Insecure Deserialization (HIGH)
**What it catches**: Unsafe deserialization of user input
**Why it matters**: Can lead to remote code execution

```javascript
// ❌ Bad - Will be flagged
const data = JSON.parse(req.body.data);
const user = eval(req.body.serialized);

// ✅ Good - Won't be flagged
const data = JSON.parse(req.body.data);
// Validate data structure
if (!data.id || typeof data.id !== 'string') {
  throw new Error('Invalid data');
}
```

**Patterns detected**:
- `JSON.parse` with unvalidated user input
- `eval` with user input
- Unsafe deserialization patterns

**Fix**: Use safe alternatives with validation

### 10. Broken Access Control (HIGH)
**What it catches**: Missing authorization checks and insecure object references
**Why it matters**: Users can access resources they shouldn't

```javascript
// ❌ Bad - Will be flagged
app.get('/users/:id', (req, res) => {
  const user = findById(req.params.id); // No ownership check
  res.json(user);
});

// ✅ Good - Won't be flagged
app.get('/users/:id', authMiddleware, (req, res) => {
  const user = findById(req.params.id);
  if (user.ownerId !== req.user.id && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.json(user);
});
```

**Patterns detected**:
- Direct object references without ownership checks
- Missing authorization in routes
- Admin functionality without proper checks

**Fix**: Implement proper authorization and ownership validation

### 11. Insecure File Upload (HIGH)
**What it catches**: Missing file validation and dangerous extensions
**Why it matters**: Can lead to remote code execution

```javascript
// ❌ Bad - Will be flagged
app.post('/upload', upload.single('file'), (req, res) => {
  // No validation
  res.json({ filename: req.file.filename });
});

// ✅ Good - Won't be flagged
app.post('/upload', upload.single('file'), (req, res) => {
  const allowedTypes = ['image/jpeg', 'image/png'];
  const allowedExtensions = ['.jpg', '.jpeg', '.png'];
  
  if (!allowedTypes.includes(req.file.mimetype)) {
    return res.status(400).json({ error: 'Invalid file type' });
  }
  
  const ext = path.extname(req.file.originalname).toLowerCase();
  if (!allowedExtensions.includes(ext)) {
    return res.status(400).json({ error: 'Invalid file extension' });
  }
  
  res.json({ filename: req.file.filename });
});
```

**Patterns detected**:
- File uploads without type checking
- Dangerous file extensions: `.php`, `.jsp`, `.exe`
- Missing file validation

**Fix**: Implement file type validation and whitelist approach

### 12. Insecure Session Management (HIGH)
**What it catches**: Weak session secrets and insecure cookies
**Why it matters**: Sessions can be hijacked or forged

```javascript
// ❌ Bad - Will be flagged
app.use(session({
  secret: 'my-secret-key',
  cookie: { secure: false, httpOnly: false }
}));

// ✅ Good - Won't be flagged
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { 
    secure: true, 
    httpOnly: true, 
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
```

**Patterns detected**:
- Weak session secrets
- Insecure cookie configurations
- Missing session security settings

**Fix**: Use strong secrets and secure cookie settings

## Medium Issues

### 13. Unvalidated Input (MEDIUM)
**What it catches**: Direct use of user input without validation
**Why it matters**: Can lead to various security issues

```javascript
// ❌ Bad - Will be flagged
const filename = req.body.filename;
fs.writeFile(filename, req.body.content);

const query = req.query.search;
const results = searchDatabase(query);

// ✅ Good - Won't be flagged
const filename = req.body.filename;
if (!filename.match(/^[a-zA-Z0-9_-]+\.txt$/)) {
  return res.status(400).json({ error: 'Invalid filename' });
}
fs.writeFile(filename, req.body.content);

const query = req.query.search;
if (typeof query !== 'string' || query.length > 100) {
  return res.status(400).json({ error: 'Invalid search query' });
}
const results = searchDatabase(query);
```

**Patterns detected**:
- File operations with user input
- Database queries without validation
- Command execution with user input

**Fix**: Validate and sanitize all user input

### 14. Insecure HTTP (MEDIUM)
**What it catches**: HTTP instead of HTTPS usage
**Why it matters**: Data transmitted in plain text

```javascript
// ❌ Bad - Will be flagged
fetch('http://api.example.com/data');
axios.get('http://localhost:3000/api/users');

// ✅ Good - Won't be flagged
fetch('https://api.example.com/data');
axios.get('https://localhost:3000/api/users');
```

**Patterns detected**:
- HTTP URLs in fetch requests
- HTTP server configurations
- API endpoints using HTTP

**Fix**: Use HTTPS for all external communications

### 15. Insecure Dependencies (MEDIUM)
**What it catches**: Vulnerable packages and suspicious dependencies
**Why it matters**: Known vulnerabilities in dependencies

```json
// ❌ Bad - Will be flagged
{
  "dependencies": {
    "lodash": "4.17.20",
    "express": "4.17.1"
  }
}

// ✅ Good - Won't be flagged
{
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.2"
  }
}
```

**Patterns detected**:
- Known vulnerable package versions
- Deprecated packages
- Suspicious package names

**Fix**: Update to secure versions or find alternatives

### 16. Missing Security Headers (MEDIUM)
**What it catches**: Missing HTTP security headers
**Why it matters**: Various attacks can be prevented with headers

```javascript
// ❌ Bad - Will be flagged
app.get('/', (req, res) => {
  res.send('Hello World');
});

// ✅ Good - Won't be flagged
app.use(helmet());
app.get('/', (req, res) => {
  res.send('Hello World');
});
```

**Patterns detected**:
- Express apps without helmet.js
- Missing security headers
- Insecure header configurations

**Fix**: Add security headers using helmet.js or manually

### 17. Insecure Random Generation (MEDIUM)
**What it catches**: Weak random number generation for security purposes
**Why it matters**: Predictable values can be exploited

```javascript
// ❌ Bad - Will be flagged
const token = Math.random().toString(36);
const password = Math.random().toString();

// ✅ Good - Won't be flagged
const token = crypto.randomBytes(32).toString('hex');
const password = crypto.randomBytes(16).toString('base64');
```

**Patterns detected**:
- `Math.random()` for security purposes
- Weak random generation
- Predictable values

**Fix**: Use cryptographically secure random generation

### 18. Insecure Logging (MEDIUM)
**What it catches**: Sensitive data exposure in logs
**Why it matters**: Logs can be accessed by unauthorized parties

```javascript
// ❌ Bad - Will be flagged
console.log('User password:', user.password);
logger.info('API key:', apiKey);
console.log('Request body:', req.body);

// ✅ Good - Won't be flagged
console.log('User login attempt:', user.email);
logger.info('API request made');
console.log('Request method:', req.method);
```

**Patterns detected**:
- Logging passwords and tokens
- Logging sensitive request data
- Logging API keys and secrets

**Fix**: Avoid logging sensitive data, use redaction

### 19. Insecure Error Handling (MEDIUM)
**What it catches**: Stack trace and information disclosure
**Why it matters**: Reveals internal system information

```javascript
// ❌ Bad - Will be flagged
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });
});

// ✅ Good - Won't be flagged
app.use((err, req, res, next) => {
  if (process.env.NODE_ENV === 'development') {
    res.status(500).json({ error: err.message });
  } else {
    res.status(500).json({ error: 'Internal server error' });
  }
});
```

**Patterns detected**:
- Stack trace exposure in production
- Detailed error messages
- Internal system information

**Fix**: Use appropriate error handling for environment

### 20. Insecure Configuration (MEDIUM)
**What it catches**: Debug mode and security features disabled
**Why it matters**: Development settings in production

```javascript
// ❌ Bad - Will be flagged
const config = {
  debug: true,
  security: false,
  cors: { origin: '*' }
};

// ✅ Good - Won't be flagged
const config = {
  debug: process.env.NODE_ENV === 'development',
  security: true,
  cors: { origin: process.env.ALLOWED_ORIGINS?.split(',') }
};
```

**Patterns detected**:
- Debug mode enabled in production
- Security features disabled
- Insecure default configurations

**Fix**: Use environment-specific configurations

### 21. AI-Generated Code Validation (MEDIUM)
**What it catches**: Potentially unsafe AI-generated code
**Why it matters**: AI can generate code with security issues

```javascript
// ❌ Bad - Will be flagged
// AI-generated code without validation
const userInput = req.body.data;
eval(userInput);

// ✅ Good - Won't be flagged
// AI-generated code with validation
const userInput = req.body.data;
if (typeof userInput === 'string' && userInput.length < 1000) {
  // Safe processing
}
```

**Patterns detected**:
- AI-generated code patterns
- Unsafe AI-generated constructs
- Missing validation in AI code

**Fix**: Review and validate AI-generated code

### 22. AI Data Leakage Prevention (MEDIUM)
**What it catches**: Sensitive data exposure in AI outputs
**Why it matters**: AI can expose confidential information

```javascript
// ❌ Bad - Will be flagged
const aiResponse = await ai.generate(`User data: ${user.secretData}`);
console.log(aiResponse);

// ✅ Good - Won't be flagged
const sanitizedData = sanitizeForAI(user.publicData);
const aiResponse = await ai.generate(`User data: ${sanitizedData}`);
```

**Patterns detected**:
- Sensitive data in AI prompts
- Unfiltered AI outputs
- Data leakage in AI responses

**Fix**: Implement data loss prevention for AI

### 23. Prompt Injection Detection (MEDIUM)
**What it catches**: Potential prompt injection vulnerabilities
**Why it matters**: Can manipulate AI behavior

```javascript
// ❌ Bad - Will be flagged
const prompt = `Translate: ${userInput}`;
const response = await ai.generate(prompt);

// ✅ Good - Won't be flagged
const sanitizedInput = escapePrompt(userInput);
const prompt = `Translate: ${sanitizedInput}`;
const response = await ai.generate(prompt);
```

**Patterns detected**:
- User input in AI prompts without sanitization
- Potential prompt injection patterns
- Unsafe prompt construction

**Fix**: Sanitize user input for AI prompts

### 24. AI Agent Access Control (MEDIUM)
**What it catches**: Missing access controls for AI agents
**Why it matters**: AI agents can access unauthorized resources

```javascript
// ❌ Bad - Will be flagged
const aiAgent = {
  access: 'all',
  permissions: '*'
};

// ✅ Good - Won't be flagged
const aiAgent = {
  access: 'restricted',
  permissions: ['read:public', 'write:own']
};
```

**Patterns detected**:
- Overly permissive AI agent configurations
- Missing access controls
- Unsafe AI agent permissions

**Fix**: Implement proper access controls for AI agents

### 25. MCP Server Security (MEDIUM)
**What it catches**: Insecure Model Context Protocol configurations
**Why it matters**: MCP servers can expose sensitive data

```javascript
// ❌ Bad - Will be flagged
const mcpConfig = {
  allow: 'all',
  auth: 'none',
  cors: '*'
};

// ✅ Good - Won't be flagged
const mcpConfig = {
  allow: ['specific-domain.com'],
  auth: 'required',
  cors: ['https://trusted-domain.com']
};
```

**Patterns detected**:
- Insecure MCP server configurations
- Missing authentication
- Overly permissive settings

**Fix**: Configure MCP servers securely

## Rule Configuration

### Customizing Rules
You can customize rule behavior by modifying the rule files in `src/rules/`. Each rule follows a consistent pattern:

```typescript
export class MyRule extends BaseRule {
  readonly name = 'my-rule';
  readonly description = 'Description of what this rule checks';
  readonly severity = 'medium' as const;

  check(fileContent: FileContent): SecurityIssue[] {
    // Your detection logic here
  }
}
```

### Adding New Rules
1. Create a new file in `src/rules/`
2. Extend the `BaseRule` class
3. Add your rule to `src/rules/index.ts`
4. Test with various code samples

### Performance Optimization
Rules are optimized for speed and accuracy:
- Specific patterns over broad ones
- Minimal false positives
- Efficient regex patterns
- Streamlined detection logic

## Best Practices

### Writing Secure Code
1. **Validate all input** - Never trust user data
2. **Use parameterized queries** - Prevent SQL injection
3. **Implement proper authentication** - Protect sensitive endpoints
4. **Use HTTPS everywhere** - Encrypt all communications
5. **Keep dependencies updated** - Patch known vulnerabilities
6. **Log safely** - Don't log sensitive data
7. **Handle errors gracefully** - Don't expose internal details

### Security Review Process
1. Run Vibe-Guard on your codebase
2. Review all flagged issues
3. Fix critical and high-risk issues immediately
4. Address medium issues in your next sprint
5. Integrate Vibe-Guard into your CI/CD pipeline
6. Run regular security scans

## Integration

### CI/CD Pipeline
```yaml
- name: Security Scan
  run: |
    curl -L https://github.com/Devjosef/vibe-guard/releases/download/v1.1.3/vibe-guard-linux-x64 -o vibe-guard
    chmod +x vibe-guard
    ./vibe-guard scan .
```

### Pre-commit Hooks
```bash
#!/bin/sh
# .git/hooks/pre-commit
./vibe-guard scan .
```

### IDE Integration
Most IDEs support running external tools. Configure Vibe-Guard to run on file save or before commits.

## Troubleshooting

### Common Issues
1. **False positives** - Check if the code is in a test file or comment
2. **Missing issues** - Ensure the file type is supported
3. **Performance issues** - Large files are automatically skipped

### Debug Mode
Run with verbose output to see more details:
```bash
vibe-guard scan . --verbose
```

## Contributing

Want to add new security rules or improve existing ones?

1. **Fork the repository**
2. **Create a new rule** following the established pattern
3. **Add tests** for your rule
4. **Update documentation** with examples
5. **Submit a pull request**

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

**Vibe-Guard: Because security shouldn't be an afterthought.** 