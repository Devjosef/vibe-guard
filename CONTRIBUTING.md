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

**Important**: Follow the optimized pattern approach - avoid redundant or overlapping patterns. Use specific, targeted patterns rather than broad ones that require filtering.

```typescript
import { BaseRule, FileContent, SecurityIssue } from '../types';

export class MyNewRule extends BaseRule {
  readonly name = 'my-new-rule';
  readonly description = 'Description of what this rule checks';
  readonly severity = 'medium' as const; // 'low' | 'medium' | 'high' | 'critical'

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    // Use specific, targeted patterns rather than broad ones
    const patterns = [
      { pattern: /specific-pattern-1/gi, type: 'Specific Issue 1' },
      { pattern: /specific-pattern-2/gi, type: 'Specific Issue 2' }
    ];
    
    for (const { pattern, type } of patterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        // Skip comments and test files
        if (this.isCommentOrTest(lineContent, fileContent.path)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          type,
          'How to fix this issue'
        ));
      }
    }
    
    return issues;
  }

  private isCommentOrTest(line: string, filePath: string): boolean {
    // Check if line is a comment
    const commentPatterns = [
      /^\s*\/\//,  // JavaScript comment
      /^\s*#/,     // Python/Shell comment
      /^\s*--/,    // SQL comment
      /^\s*<!--/,  // HTML comment
    ];

    if (commentPatterns.some(pattern => pattern.test(line))) {
      return true;
    }

    // Check if it's a test file
    const testPatterns = [/test/i, /spec/i, /__tests__/i, /\.test\./i, /\.spec\./i];
    return testPatterns.some(pattern => pattern.test(filePath));
  }
}
```

3. Add your rule to `src/rules/index.ts`:
   - Import your rule
   - Add it to the `getAllRules()` function
   - Export it in the exports section

4. Test your rule with various code samples
5. Update the README and SECURITY_RULES.md with your new rule

## Rule files and lint exceptions

Rule implementations under `src/rules/` operate on raw source text and ASTs and intentionally use
regexes, special characters, and sometimes `any` for AST node typing. Because of that, some
automatic lint rules can produce noisy false positives for perfectly valid rule code.

We provide a focused ESLint override for `src/rules/**` (see `.eslintrc.cjs`) that relaxes a small
set of rules such as `no-useless-escape`, `@typescript-eslint/no-explicit-any`,
`@typescript-eslint/no-var-requires`, and `prefer-const` so contributors aren't blocked by false
positives while working on rules.

Guidance for contributors:

- Prefer using the shared override in `.eslintrc.cjs` rather than disabling rules project-wide.
- If only a single file needs a targeted exception, prefer a file-level comment with a brief
  justification, for example:

```ts
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- uses raw AST nodes
const node: any = parseSomeAst(...);
```

- Always document the reason for any lint disablement in your PR so reviewers can evaluate the
  trade-offs.
- Run `npm run lint` locally and include lint results in your PR description if you make
  intentional exceptions.

Keeping exceptions small and well-documented helps reviewers and maintainers keep the rule set
secure and maintainable.

## Performance Optimization Guidelines

When adding or modifying security rules, follow these optimization principles:

### Pattern Design Best Practices
- **Avoid Redundant Patterns**: Don't create overlapping patterns that catch the same issues
- **Use Specific Patterns**: Target specific vulnerabilities rather than broad patterns that require filtering
- **Consolidate Similar Patterns**: Group related patterns into single, efficient regex
- **Eliminate "Catch All" Patterns**: Avoid patterns that match everything then filter out false positives

### Examples of Good vs Bad Patterns

**❌ Bad - Redundant Patterns:**
```typescript
// Multiple overlapping patterns
{ pattern: /req\.body\.password/gi, type: 'Password in body' },
{ pattern: /req\.body\.[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Any body field' }
```

**✅ Good - Consolidated Pattern:**
```typescript
// Single, specific pattern
{ pattern: /req\.body\.[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Request body field' }
```

**❌ Bad - Catch All Then Filter:**
```typescript
// Broad pattern with filtering
{ pattern: /(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, type: 'User input' }
// Then filter out false positives...
```

**✅ Good - Specific Patterns:**
```typescript
// Specific patterns for different use cases
{ pattern: /req\.body\.[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Request body field' },
{ pattern: /req\.query\.[a-zA-Z_][a-zA-Z0-9_]*/gi, type: 'Query parameter' }
```

## Code Style

- Use TypeScript with strict typing
- Use meaningful variable names
- Write clear, concise comments
- Follow the existing code structure
- Use consistent formatting

### TypeScript Guidelines
```typescript
// ✅ Good
export class MyRule extends BaseRule {
  readonly name = 'my-rule';
  readonly description = 'Clear description';
  readonly severity = 'medium' as const;

  check(fileContent: FileContent): SecurityIssue[] {
    // Implementation
  }
}

// ❌ Bad
export class MyRule extends BaseRule {
  name = 'my-rule'; // Missing readonly
  description = 'Description'; // Missing readonly
  severity = 'medium'; // Missing as const
}
```

### Naming Conventions
- **Files**: kebab-case (e.g., `my-new-rule.ts`)
- **Classes**: PascalCase (e.g., `MyNewRule`)
- **Variables**: camelCase (e.g., `myVariable`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_FILE_SIZE`)

## Testing Guidelines

### Writing Tests
Every rule should have comprehensive tests:

```typescript
// src/__tests__/rules/my-new-rule.test.ts
import { MyNewRule } from '../../rules/my-new-rule';

describe('MyNewRule', () => {
  const rule = new MyNewRule();

  it('detects specific vulnerability', () => {
    const content = `
      // Vulnerable code here
      const badCode = "something bad";
    `;

    const issues = rule.check({ content, path: 'test.js', lines: content.split('\n') });
    
    expect(issues).toHaveLength(1);
    expect(issues[0].type).toBe('Specific Issue 1');
  });

  it('ignores safe code', () => {
    const content = `
      // Safe code here
      const goodCode = "something good";
    `;

    const issues = rule.check({ content, path: 'test.js', lines: content.split('\n') });
    
    expect(issues).toHaveLength(0);
  });

  it('ignores comments and test files', () => {
    const content = `
      // This is a comment with bad code
      // const badCode = "something bad";
    `;

    const issues = rule.check({ content, path: 'test.js', lines: content.split('\n') });
    
    expect(issues).toHaveLength(0);
  });
});
```

### Test Coverage
- Test positive cases (vulnerabilities detected)
- Test negative cases (safe code ignored)
- Test edge cases (comments, test files, etc.)
- Test different file types and languages

## Documentation Guidelines

### Updating README.md
When adding a new rule:
1. Add it to the appropriate severity section
2. Update the rule count
3. Provide a brief description

### Updating SECURITY_RULES.md
For each new rule, add:
1. **What it catches**: Brief description
2. **Why it matters**: Security impact
3. **Code examples**: Bad vs good code
4. **Patterns detected**: What the rule looks for
5. **Fix**: How to resolve the issue

### Example Documentation
```markdown
### 26. My New Rule (MEDIUM)
**What it catches**: Description of the vulnerability
**Why it matters**: Security impact explanation

```javascript
// ❌ Bad - Will be flagged
const badCode = "vulnerable pattern";

// ✅ Good - Won't be flagged
const goodCode = "safe pattern";
```

**Patterns detected**:
- Pattern 1: Description
- Pattern 2: Description

**Fix**: How to fix the issue
```

## Pull Request Process

### Before Submitting
1. **Run tests**: `npm test`
2. **Check linting**: Ensure code follows style guidelines
3. **Update documentation**: README and SECURITY_RULES.md
4. **Test your changes**: Run Vibe-Guard on sample code

### PR Description
Include:
- **What**: Brief description of changes
- **Why**: Why the change is needed
- **How**: How the change works
- **Testing**: What you tested

### Example PR Description
```
## What
Added new rule to detect insecure cookie configurations

## Why
Cookies without proper security settings can lead to session hijacking

## How
- Created `InsecureCookieRule` class
- Added patterns for missing httpOnly, secure, sameSite attributes
- Integrated with existing rule system

## Testing
- Added comprehensive test suite
- Tested on real-world examples
- Verified no false positives on safe code
```

## Review Process

### What We Look For
- **Correctness**: Does the rule work as intended?
- **Performance**: Is it optimized and efficient?
- **Documentation**: Is it well-documented?
- **Tests**: Are there comprehensive tests?
- **Style**: Does it follow our guidelines?

### Common Issues
- **Redundant patterns**: Overlapping detection logic
- **Missing tests**: Incomplete test coverage
- **Poor documentation**: Unclear explanations
- **Performance issues**: Slow or inefficient patterns

## Getting Help

### Questions?
- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and ideas
- **Documentation**: Check existing docs first

### Resources
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Security Best Practices](https://owasp.org/www-project-top-ten/)
- [Regex Testing](https://regex101.com/)

## Recognition

Contributors are recognized in:
- **README.md**: For significant contributions
- **CHANGELOG.md**: For all contributions
- **GitHub**: Through the contributors graph

## License

By contributing to Vibe-Guard, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to Vibe-Guard! ██** 