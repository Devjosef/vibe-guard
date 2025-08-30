# Testing Standards & Guidelines

## Overview

This document outlines the testing standards and guidelines for the VibeGuard security scanner. All tests should follow these principles to ensure maintainable, reliable, and valuable test coverage.

## Core Principles

### 1. TDD (Test-Driven Development) Approach
- **Test behavior, not implementation details**
- **Write tests first** to drive design decisions
- **Focus on what the code should do**, not how it does it
- **Never warp tests to make them passable** - fix the implementation instead

### 2. Clean Code Principles
- **Single Responsibility** - Each test has one clear purpose
- **DRY (Don't Repeat Yourself)** - Avoid redundant test code
- **Readable and self-documenting** - Test names should explain the scenario
- **Maintainable** - Easy to understand and modify

### 3. Test Structure Guidelines
- **Isolated tests** - Each test should be independent
- **Focused scope** - Test specific behaviors, not entire classes
- **Edge case coverage** - Include boundary conditions and error scenarios
- **Framework-agnostic** - Tests should work regardless of implementation details

## Test File Structure

### Standard Test Organization
```typescript
describe('RuleName', () => {
  let rule: RuleClass;

  beforeEach(() => {
    rule = new RuleClass();
  });

  describe('Rule Properties', () => {
    it('should have correct basic properties', () => {
      // Test rule metadata
    });
  });

  describe('Core Functionality', () => {
    it('should detect [specific behavior]', () => {
      // Test main functionality
    });

    it('should NOT detect [safe scenario]', () => {
      // Test false positive prevention
    });
  });

  describe('Edge Cases', () => {
    it('should handle [complex scenario]', () => {
      // Test edge cases
    });
  });

  describe('Context-Aware Behavior', () => {
    it('should adjust behavior based on [context]', () => {
      // Test contextual logic
    });
  });
});
```

### Test Categories

#### 1. Rule Properties
- Test basic rule metadata (name, description, severity)
- Ensure rule is properly configured

#### 2. Core Functionality
- Test the main detection logic
- Cover positive cases (should detect)
- Cover negative cases (should NOT detect)

#### 3. Framework-Specific Behavior
- Test framework detection and suggestions
- Ensure appropriate remediation advice

#### 4. Edge Cases
- Complex input patterns
- Boundary conditions
- False positive prevention

#### 5. Context-Aware Logic
- Development vs production environments
- File type considerations
- Severity adjustments

## Test Writing Guidelines

### Test Naming Convention
```typescript
// ✅ Good - Clear and descriptive
it('should detect XSS with user input in innerHTML', () => {
it('should NOT detect XSS when DOMPurify is used', () => {
it('should downgrade severity in development context', () => {

// ❌ Bad - Vague and unclear
it('should work correctly', () => {
it('should handle edge cases', () => {
it('should not break', () => {
```

### Test Content Structure
```typescript
it('should detect [specific behavior]', () => {
  // 1. Arrange - Set up test data
  const content = 'specific test scenario';
  const fileContent: FileContent = {
    path: 'src/test-file.js',
    content,
    lines: [content]
  };

  // 2. Act - Execute the rule
  const issues = rule.check(fileContent);

  // 3. Assert - Verify results
  expect(issues).toHaveLength(1);
  expect(issues[0].severity).toBe('critical');
  expect(issues[0].message).toContain('specific message');
});
```

### Assertion Guidelines
```typescript
// ✅ Good - Specific and meaningful assertions
expect(issues).toHaveLength(1);
expect(issues[0].severity).toBe('critical');
expect(issues[0].message).toContain('specific message');
expect(issues[0].suggestion).toContain('framework-specific advice');

// ❌ Bad - Generic and unhelpful assertions
expect(issues.length).toBeGreaterThan(0);
expect(issues.some(issue => issue.severity === 'critical')).toBe(true);
```

## Security Rule Testing Standards

### 1. Vulnerability Detection Tests
- **Test positive cases** - Code that should trigger the rule
- **Test negative cases** - Safe code that should NOT trigger the rule
- **Test sanitization** - Code that uses proper security measures
- **Test edge cases** - Complex patterns and boundary conditions

### 2. Severity Level Testing
- **Critical** - Direct security vulnerabilities
- **High** - Potential security risks
- **Medium** - Framework-specific risks
- **Low** - Legacy or deprecated patterns

### 3. Framework Detection Testing
- **React** - dangerouslySetInnerHTML, JSX patterns
- **Vue** - v-html directive, Vue-specific patterns
- **Angular** - innerHTML binding, Angular-specific patterns
- **jQuery** - html(), append() methods
- **Server-side** - PHP, Python, .NET patterns

### 4. Context-Aware Testing
- **Development environment** - Severity downgrades
- **Test files** - Different behavior for test contexts
- **Production files** - Full severity enforcement
- **File extensions** - Language-specific detection

## Test Data Guidelines

### File Content Structure
```typescript
const fileContent: FileContent = {
  path: 'src/meaningful-filename.js',  // Descriptive filename
  content: 'specific test scenario',   // Minimal, focused content
  lines: ['specific test scenario']    // Array of lines
};
```

### Test Content Examples
```typescript
// ✅ Good - Clear, focused test scenarios
const content = 'element.innerHTML = req.body.html;';
const content = '<div dangerouslySetInnerHTML={{ __html: req.body.html }} />';
const content = 'echo $_GET["data"];';

// ❌ Bad - Unclear or overly complex scenarios
const content = `
  // Lots of unrelated code
  element.innerHTML = req.body.html;
  // More unrelated code
`;
```

## Performance Considerations

### Test Efficiency
- **Minimal test data** - Use only what's necessary
- **Focused assertions** - Test specific behaviors
- **Avoid large files** - Keep test files small and focused
- **Reasonable timeouts** - Tests should complete quickly

### Large File Testing
```typescript
// Only test large files when specifically needed
it('should handle large files efficiently', () => {
  const largeContent = Array(1000).fill('const safe = "content";').join('\n');
  const xssLine = 'element.innerHTML = req.body.html;';
  const content = largeContent + '\n' + xssLine + '\n' + largeContent;
  
  const startTime = Date.now();
  const issues = rule.check(fileContent);
  const endTime = Date.now();

  expect(issues).toHaveLength(1);
  expect(endTime - startTime).toBeLessThan(1000); // 1 second timeout
});
```

## Common Anti-Patterns to Avoid

### 1. Test Bloat
```typescript
// ❌ Bad - Testing every possible variation
it('should detect innerHTML with req.body', () => { /* ... */ });
it('should detect innerHTML with req.query', () => { /* ... */ });
it('should detect innerHTML with req.params', () => { /* ... */ });
it('should detect innerHTML with flask.request', () => { /* ... */ });
// ... 20 more similar tests

// ✅ Good - Test the core behavior
it('should detect direct DOM manipulation with user input', () => { /* ... */ });
```

### 2. Implementation Testing
```typescript
// ❌ Bad - Testing implementation details
it('should use regex pattern X', () => {
  expect(rule.patterns).toContain(/specific-regex/);
});

// ✅ Good - Testing behavior
it('should detect XSS vulnerability', () => {
  const issues = rule.check(fileContent);
  expect(issues).toHaveLength(1);
});
```

### 3. Over-Engineering
```typescript
// ❌ Bad - Complex test setup for simple scenarios
it('should detect XSS', () => {
  const mockFileSystem = createMockFileSystem();
  const mockParser = createMockParser();
  const mockValidator = createMockValidator();
  // ... 50 lines of setup
});

// ✅ Good - Simple, focused test
it('should detect XSS', () => {
  const fileContent = { path: 'test.js', content: 'element.innerHTML = req.body.html;', lines: ['element.innerHTML = req.body.html;'] };
  const issues = rule.check(fileContent);
  expect(issues).toHaveLength(1);
});
```

## Test Maintenance

### 1. Regular Review
- **Review test coverage** - Ensure all behaviors are tested
- **Remove obsolete tests** - Delete tests for removed functionality
- **Update test data** - Keep test scenarios current
- **Refactor test code** - Improve readability and maintainability

### 2. Test Documentation
- **Clear test names** - Self-documenting test descriptions
- **Meaningful comments** - Explain complex test scenarios
- **Updated guidelines** - Keep this document current

### 3. Test Organization
- **Logical grouping** - Group related tests together
- **Consistent structure** - Follow established patterns
- **Easy navigation** - Clear describe/it hierarchy

## Quality Checklist

Before committing tests, ensure:

- [ ] Tests follow TDD principles
- [ ] Each test has a single, clear purpose
- [ ] Test names are descriptive and self-documenting
- [ ] Tests are isolated and independent
- [ ] Edge cases are covered
- [ ] False positives are prevented
- [ ] Performance is reasonable
- [ ] Code is clean and maintainable
- [ ] Tests pass consistently
- [ ] Documentation is updated

## Examples

### Good Test Example
```typescript
describe('XssDetectionRule', () => {
  let rule: XssDetectionRule;

  beforeEach(() => {
    rule = new XssDetectionRule();
  });

  describe('Critical XSS Detection', () => {
    it('should detect direct DOM manipulation with user input', () => {
      const content = 'element.innerHTML = req.body.html;';
      const fileContent: FileContent = {
        path: 'src/critical-xss.js',
        content,
        lines: [content]
      };

      const issues = rule.check(fileContent);
      expect(issues).toHaveLength(1);
      expect(issues[0].severity).toBe('critical');
      expect(issues[0].message).toContain('DOM manipulation with user input');
    });
  });
});
```

This standard ensures that all tests in the VibeGuard project are:
- **Focused** on behavior, not implementation
- **Maintainable** and easy to understand
- **Reliable** and consistent
- **Valuable** for catching regressions
- **Efficient** and performant
