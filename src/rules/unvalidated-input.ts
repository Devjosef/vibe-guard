import { BaseRule, FileContent, SecurityIssue } from '../types';

export class UnvalidatedInputRule extends BaseRule {
  readonly name = 'unvalidated-input';
  readonly description = 'Detects potentially unvalidated user input';
  readonly severity = 'medium' as const;

  private readonly inputPatterns = [
    // Express.js patterns
    { pattern: /req\.(?:body|query|params)\.[a-zA-Z_][a-zA-Z0-9_]*(?!\s*\.\s*(?:validate|sanitize|escape|trim|length|match|test))/g, type: 'Express request parameter' },
    { pattern: /req\.(?:body|query|params)(?!\s*\.\s*(?:validate|sanitize|escape))/g, type: 'Express request object' },
    
    // Direct user input usage
    { pattern: /(?:eval|exec|system|shell_exec)\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.)/gi, type: 'Code execution with user input' },
    { pattern: /(?:innerHTML|outerHTML)\s*=\s*(?:req\.|request\.|input\.|params\.|query\.)/gi, type: 'DOM manipulation with user input' },
    
    // File operations with user input
    { pattern: /(?:readFile|writeFile|unlink|rmdir|mkdir)\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.)/gi, type: 'File operation with user input' },
    { pattern: /(?:open|fopen|file_get_contents)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP file operation with user input' },
    
    // Database operations without validation
    { pattern: /\.(?:query|exec|execute)\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.)(?![^)]*(?:validate|sanitize|escape))/gi, type: 'Database query with unvalidated input' },
    
    // Command injection patterns
    { pattern: /(?:spawn|exec|execSync)\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.)/gi, type: 'Command execution with user input' },
    
    // Python patterns
    { pattern: /(?:os\.system|subprocess\.call|eval|exec)\s*\(\s*(?:request\.|flask\.request\.)/gi, type: 'Python system call with user input' },
    
    // PHP patterns
    { pattern: /(?:system|exec|shell_exec|passthru)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP system call with user input' },
    { pattern: /(?:include|require|include_once|require_once)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP file inclusion with user input' },
    
    // Java patterns
    { pattern: /Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:request\.getParameter|request\.getAttribute)/gi, type: 'Java runtime execution with user input' },
    
    // Generic patterns
    { pattern: /\$\{(?:req\.|request\.|input\.|params\.|query\.)[^}]+\}/g, type: 'Template literal with user input' }
  ];

  private readonly validationPatterns = [
    /validate/i,
    /sanitize/i,
    /escape/i,
    /filter/i,
    /clean/i,
    /trim/i,
    /strip/i,
    /whitelist/i,
    /blacklist/i,
    /check/i,
    /verify/i,
    /isValid/i,
    /typeof/i,
    /instanceof/i,
    /\.length\s*[><=]/,
    /\.match\s*\(/,
    /\.test\s*\(/,
    /parseInt/i,
    /parseFloat/i,
    /Number\(/,
    /String\(/,
    /Boolean\(/
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, type } of this.inputPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        // Skip if validation is present in the same line or nearby lines
        if (this.hasValidationNearby(fileContent.content, line)) {
          continue;
        }

        // Skip if it's in a comment or test file
        if (this.isCommentOrTest(lineContent, fileContent.path)) {
          continue;
        }

        // Skip if it's just a simple property access for logging or display
        if (this.isSimplePropertyAccess(lineContent)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Potentially unvalidated user input: ${type}`,
          `Validate and sanitize user input before use. Consider using validation libraries like Joi, express-validator, or built-in validation methods.`
        ));
      }
    }

    return issues;
  }

  private hasValidationNearby(content: string, lineNumber: number): boolean {
    const lines = content.split('\n');
    const contextRange = 3; // Check 3 lines before and after
    
    const startLine = Math.max(0, lineNumber - contextRange - 1);
    const endLine = Math.min(lines.length, lineNumber + contextRange);
    
    const contextLines = lines.slice(startLine, endLine).join('\n');
    
    return this.validationPatterns.some(pattern => pattern.test(contextLines));
  }

  private isCommentOrTest(line: string, filePath: string): boolean {
    // Check if line is a comment
    const commentPatterns = [
      /^\s*\/\//,  // JavaScript comment
      /^\s*#/,     // Python/Shell comment
      /^\s*\*/     // Multi-line comment
    ];

    if (commentPatterns.some(pattern => pattern.test(line))) {
      return true;
    }

    // Check if it's a test file
    const testPatterns = [
      /test/i,
      /spec/i,
      /\.test\./i,
      /\.spec\./i,
      /__tests__/i,
      /tests\//i,
      /spec\//i
    ];

    return testPatterns.some(pattern => pattern.test(filePath));
  }

  private isSimplePropertyAccess(line: string): boolean {
    // Check if it's just logging, console output, or simple assignment
    const safePatterns = [
      /console\./i,
      /log\(/i,
      /print\(/i,
      /echo\s/i,
      /return\s/i,
      /res\.json\s*\(/i,
      /res\.send\s*\(/i,
      /JSON\.stringify/i
    ];

    return safePatterns.some(pattern => pattern.test(line));
  }
} 