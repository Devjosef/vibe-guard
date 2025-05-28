# Contributing to Vibe-Guard

We love your input! We want to make contributing to Vibe-Guard as easy and transparent as possible.

## Development Process

1. Fork the repo and create your branch from `main`
2. If you've added code, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code lints
6. Issue that pull request!

## Getting Started

```bash
# Clone your fork
git clone https://github.com/your-username/vibe-guard.git
cd vibe-guard

# Install dependencies
npm install

# Build the project
npm run build

# Test your changes
node dist/bin/vibe-guard.js scan .

# Create standalone binaries (optional)
npm run package:all
```

## Adding New Security Rules

To add a new security rule:

1. Create a new file in `src/rules/` (e.g., `my-new-rule.ts`)
2. Extend the `BaseRule` class:

```typescript
import { BaseRule, FileContent, SecurityIssue } from '../types';

export class MyNewRule extends BaseRule {
  readonly name = 'my-new-rule';
  readonly description = 'Description of what this rule checks';
  readonly severity = 'medium' as const; // 'low' | 'medium' | 'high' | 'critical'

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    // Your detection logic here
    const pattern = /your-regex-pattern/gi;
    const matches = this.findMatches(fileContent.content, pattern);
    
    for (const { match, line, column, lineContent } of matches) {
      // Skip false positives
      if (this.isFalsePositive(match[0])) {
        continue;
      }

      issues.push(this.createIssue(
        fileContent.path,
        line,
        column,
        lineContent,
        'Issue description',
        'How to fix this issue'
      ));
    }
    
    return issues;
  }

  private isFalsePositive(text: string): boolean {
    // Add your false positive detection logic
    const falsePositivePatterns = [
      /test/i,
      /example/i,
      /demo/i,
      /placeholder/i
    ];
    
    return falsePositivePatterns.some(pattern => pattern.test(text));
  }
}
```

3. Add your rule to `src/rules/index.ts`:
   - Import your rule
   - Add it to the `getAllRules()` function
   - Export it in the exports section

4. Test your rule with various code samples
5. Update the README and SECURITY_RULES.md with your new rule

## Code Style

- Use TypeScript with strict typing
- Use meaningful variable names
- Add comments for complex logic
- Follow the existing code style
- Use async/await instead of promises where possible
- Prefer `const` over `let`, avoid `var`
- Handle edge cases gracefully (binary files, large files, encoding issues)

## Edge Case Handling

Vibe-Guard includes robust edge case handling. When adding new rules, consider:

### File Processing Edge Cases

**Binary Files** - Automatically skipped
```typescript
// The scanner handles this automatically
// Your rules won't see binary files
```

**Large Files** - Files >5MB are automatically skipped
```typescript
// No need to handle in your rules
// Scanner prevents memory issues
```

**Encoding Issues** - Handled gracefully
```typescript
// Scanner handles UTF-8 decoding errors
// Your rules get clean text content
```

### False Positive Prevention

**Test Files & Development Code**
```typescript
// Should NOT trigger - it's in a test file
const mockApiKey = "sk_test_fake_key_for_testing";

// Should NOT trigger - obvious placeholder
const API_KEY = "your-api-key-here";
const PASSWORD = "password123"; // in example code
```

**Environment Variables & Templates**
```typescript
// Should NOT trigger - using env vars correctly
const apiKey = process.env.API_KEY;
const dbUrl = `mongodb://${process.env.DB_USER}:${process.env.DB_PASS}@localhost`;

// Should NOT trigger - template variables
const config = "database_url: ${DATABASE_URL}";
const windowsVar = "%API_KEY%";
const templateVar = "{{SECRET_KEY}}";
```

**Development/Local Contexts**
```typescript
// Should NOT trigger - localhost development
app.use(cors({ origin: 'http://localhost:3000' }));
fetch('http://localhost:8080/api/data');

// Should NOT trigger - development environment
if (process.env.NODE_ENV === 'development') {
  // Less strict security for dev
}
```

**Repeated Characters & Simple Patterns**
```typescript
// Should NOT trigger - obvious test values
const testKey = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const zeroKey = "00000000000000000000000000000000";
const simplePattern = "123456789012345678901234567890";
```

### Complex Patterns to Handle

**Multi-line Secrets**
```typescript
// Should trigger - real secret split across lines
const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7...
-----END RSA PRIVATE KEY-----`;
```

**Base64 Encoded Secrets**
```typescript
// Should trigger - base64 encoded real secrets
const secret = "c2VjcmV0LWFwaS1rZXktMTIzNDU2Nzg5MA=="; // real secret encoded

// Should NOT trigger - test base64
const testSecret = "dGVzdC1zZWNyZXQ="; // "test-secret" encoded
```

**Context-Dependent Issues**
```typescript
// Should trigger in production files, not in test files
const query = "SELECT * FROM users WHERE id = " + userId;

// Should consider validation context
app.post('/upload', (req, res) => {
  // This is bad without validation
  fs.writeFile(req.body.filename, data);
  
  // This might be OK with proper validation nearby
  if (isValidFilename(req.body.filename)) {
    fs.writeFile(req.body.filename, data);
  }
});
```

**Import Statements** - Automatically handled
```typescript
// Should NOT trigger directory traversal
import { BaseRule } from '../types';
const utils = require('../utils');
export { something } from '../helpers';
```

### Language-Specific Quirks

**JavaScript/TypeScript**
- Template literals vs string concatenation
- Dynamic imports and requires
- Async/await vs Promise patterns
- Variable naming patterns (avoid matching variable names)

**Python**
- f-strings vs % formatting vs .format()
- Different import styles
- Virtual environment paths

**Configuration Files**
- YAML vs JSON vs TOML different syntax
- Comments in different formats
- Environment variable substitution

### Performance Considerations

**Regex Efficiency**
```typescript
// Good - specific, efficient regex
/sk_live_[a-zA-Z0-9]{24}/g

// Bad - overly broad, slow regex
/.*secret.*password.*/gi

// Good - negative lookbehind for context
/(?<!import\s+['"`][^'"`]*)\.\.\//g

// Bad - will match import statements
/\.\.\//g
```

**Pattern Specificity**
```typescript
// Good - specific context
/(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi

// Bad - too broad, catches variable names
/token\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi

// Better - avoid variable names
/(?:^|[^a-zA-Z0-9_])(?:token|auth)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi
```

### Testing Your Rules

Always test with:
- Real vulnerable code samples
- Common false positive scenarios
- Different file encodings (UTF-8, UTF-16)
- Files with no newline at end
- Empty files
- Very long lines
- Mixed line endings (CRLF vs LF)
- Binary files (should be skipped automatically)
- Large files (should be skipped automatically)
- Test files and mock data
- Import/export statements
- Environment variable usage

```bash
# Test with various file types
echo "const secret = 'real-secret-key-123456789';" > test-real.js
echo "const testKey = 'test-placeholder';" > test-false-positive.js
echo "import utils from '../utils';" > test-import.js

# Run your rule
node dist/bin/vibe-guard.js scan test-*.js

# Test with binary file (should be skipped)
echo -e '\x00\x01\x02\x03' > test.bin
node dist/bin/vibe-guard.js scan test.bin

# Test with large file (should be skipped)
dd if=/dev/zero of=large.txt bs=1024 count=6000
node dist/bin/vibe-guard.js scan large.txt
```

## Testing

```bash
# Build the project
npm run build

# Run the tool on test files
node dist/bin/vibe-guard.js scan test-file.js

# Test with different output formats
node dist/bin/vibe-guard.js scan . --format json
node dist/bin/vibe-guard.js scan . --format table

# Run TypeScript compiler (catches type errors)
npm run build

# Create test binaries
npm run package:macos
npm run package:linux
npm run package:windows
```

## Reporting Bugs

We use GitHub issues to track public bugs. Report a bug by opening a new issue.

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening)
- Your platform (macOS, Linux, Windows)
- How you installed Vibe-Guard (binary, npm, docker)
- Sample code that triggers the issue (if applicable)

## License

By contributing, you agree that your contributions will be licensed under the MIT License. 