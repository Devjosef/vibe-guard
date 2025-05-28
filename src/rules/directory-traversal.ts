import { BaseRule, FileContent, SecurityIssue } from '../types';

export class DirectoryTraversalRule extends BaseRule {
  readonly name = 'directory-traversal';
  readonly description = 'Detects potential directory traversal vulnerabilities';
  readonly severity = 'high' as const;

  private readonly traversalPatterns = [
    // Direct path traversal patterns
    { pattern: /(?:readFile|writeFile|createReadStream|createWriteStream|unlink|rmdir|mkdir|stat|access)\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.)[^)]*(?!\s*(?:path\.resolve|path\.join|path\.normalize))/gi, type: 'File operation with user input' },
    
    // Express static file serving
    { pattern: /express\.static\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.)/gi, type: 'Express static serving with user input' },
    { pattern: /res\.sendFile\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.)/gi, type: 'Express sendFile with user input' },
    
    // Path concatenation
    { pattern: /['"`][^'"`]*\/['"`]\s*\+\s*(?:req\.|request\.|input\.|params\.|query\.)/gi, type: 'Path concatenation with user input' },
    { pattern: /\$\{[^}]*(?:req\.|request\.|input\.|params\.|query\.)[^}]*\}/g, type: 'Template literal path with user input' },
    
    // Dangerous path patterns (but not in imports/requires)
    { pattern: /(?<!(?:import|require|from)\s+['"`][^'"`]*)\.\.\//g, type: 'Hardcoded directory traversal sequence' },
    
    // Framework-specific patterns
    { pattern: /File\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.)/gi, type: 'File constructor with user input' },
    { pattern: /FileInputStream\s*\(\s*(?:request\.getParameter|request\.getAttribute)/gi, type: 'Java FileInputStream with user input' },
    { pattern: /fopen\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP fopen with user input' },
    { pattern: /file_get_contents\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP file_get_contents with user input' },
    
    // Python patterns
    { pattern: /open\s*\(\s*(?:request\.|flask\.request\.)/gi, type: 'Python file open with user input' },
    { pattern: /os\.path\.join\s*\([^)]*(?:request\.|flask\.request\.)/gi, type: 'Python path join with user input' },
    
    // Node.js path operations
    { pattern: /path\.join\s*\([^)]*(?:req\.|request\.|input\.|params\.|query\.)(?![^)]*(?:path\.resolve|path\.normalize))/gi, type: 'Path join without normalization' },
    
    // Include/require with user input
    { pattern: /(?:require|import)\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.)/gi, type: 'Module import with user input' },
    { pattern: /(?:include|require|include_once|require_once)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, type: 'PHP include with user input' }
  ];

  private readonly safePatterns = [
    /path\.resolve/i,
    /path\.normalize/i,
    /path\.basename/i,
    /sanitize/i,
    /validate/i,
    /whitelist/i,
    /allowedPaths/i,
    /isValidPath/i,
    /checkPath/i,
    /\.replace\s*\(\s*\/\.\.\//gi,
    /\.replace\s*\(\s*\/\.\.\\/gi,
    /filter/i,
    /startsWith/i,
    /includes.*allowed/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, type } of this.traversalPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        // Skip if safe path handling is present
        if (this.hasSafePathHandling(fileContent.content, line)) {
          continue;
        }

        // Skip if it's in a comment or test file
        if (this.isCommentOrTest(lineContent, fileContent.path)) {
          continue;
        }

        // Skip if it's an import/require statement
        if (this.isImportStatement(lineContent)) {
          continue;
        }

        // Skip if it's a hardcoded traversal in a test context
        if (type === 'Hardcoded directory traversal sequence' && this.isTestContext(fileContent.content, line)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Potential directory traversal vulnerability: ${type}`,
          `Validate and sanitize file paths. Use path.resolve(), path.normalize(), or whitelist allowed directories. Never trust user input for file paths.`
        ));
      }
    }

    return issues;
  }

  private hasSafePathHandling(content: string, lineNumber: number): boolean {
    const lines = content.split('\n');
    const contextRange = 5; // Check 5 lines before and after
    
    const startLine = Math.max(0, lineNumber - contextRange - 1);
    const endLine = Math.min(lines.length, lineNumber + contextRange);
    
    const contextLines = lines.slice(startLine, endLine).join('\n');
    
    return this.safePatterns.some(pattern => pattern.test(contextLines));
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

  private isImportStatement(line: string): boolean {
    const importPatterns = [
      /^\s*import\s+.*from\s+['"`]/,
      /^\s*import\s+['"`]/,
      /^\s*const\s+.*=\s+require\s*\(\s*['"`]/,
      /^\s*let\s+.*=\s+require\s*\(\s*['"`]/,
      /^\s*var\s+.*=\s+require\s*\(\s*['"`]/,
      /^\s*export\s+.*from\s+['"`]/,
      /^\s*from\s+['"`]/
    ];

    return importPatterns.some(pattern => pattern.test(line));
  }

  private isTestContext(content: string, lineNumber: number): boolean {
    const lines = content.split('\n');
    const contextRange = 3;
    
    const startLine = Math.max(0, lineNumber - contextRange - 1);
    const endLine = Math.min(lines.length, lineNumber + contextRange);
    
    const contextLines = lines.slice(startLine, endLine).join('\n');
    
    const testPatterns = [
      /test/i,
      /spec/i,
      /describe/i,
      /it\(/i,
      /expect/i,
      /assert/i,
      /mock/i,
      /example/i,
      /demo/i
    ];

    return testPatterns.some(pattern => pattern.test(contextLines));
  }
} 