import { BaseRule, FileContent, SecurityIssue } from '../types';

export class SqlInjectionRule extends BaseRule {
  readonly name = 'sql-injection';
  readonly description = 'Detects potential SQL injection vulnerabilities';
  readonly severity = 'high' as const;

  private readonly sqlInjectionPatterns = [
    // String concatenation in SQL
    { pattern: /(?:query|sql|execute)\s*\(\s*['"`][^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'String concatenation in SQL query' },
    { pattern: /['"`]SELECT\s+[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'SELECT query with concatenation' },
    { pattern: /['"`]INSERT\s+[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'INSERT query with concatenation' },
    { pattern: /['"`]UPDATE\s+[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'UPDATE query with concatenation' },
    { pattern: /['"`]DELETE\s+[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'DELETE query with concatenation' },
    
    // Template literals with variables
    { pattern: /`SELECT\s+[^`]*\$\{[^}]+\}[^`]*`/gi, type: 'Template literal SQL with variables' },
    { pattern: /`INSERT\s+[^`]*\$\{[^}]+\}[^`]*`/gi, type: 'Template literal INSERT with variables' },
    { pattern: /`UPDATE\s+[^`]*\$\{[^}]+\}[^`]*`/gi, type: 'Template literal UPDATE with variables' },
    { pattern: /`DELETE\s+[^`]*\$\{[^}]+\}[^`]*`/gi, type: 'Template literal DELETE with variables' },
    
    // String formatting in SQL
    { pattern: /(?:query|sql)\s*=\s*['"`][^'"`]*%s[^'"`]*['"`]\s*%\s*\(/gi, type: 'Python string formatting in SQL' },
    { pattern: /(?:query|sql)\s*=\s*f['"`][^'"`]*\{[^}]+\}[^'"`]*['"`]/gi, type: 'Python f-string in SQL' },
    { pattern: /String\.format\s*\(\s*['"`][^'"`]*\{[^}]*\}[^'"`]*['"`]/gi, type: 'Java String.format in SQL' },
    
    // Direct variable insertion
    { pattern: /WHERE\s+[^'"`\s]+\s*=\s*['"`]?\s*\+\s*[^'"`\s)]+/gi, type: 'WHERE clause with concatenation' },
    { pattern: /WHERE\s+[^'"`\s]+\s*=\s*\$\{[^}]+\}/gi, type: 'WHERE clause with template variable' },
    
    // Framework-specific patterns
    { pattern: /\.query\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'Database query with concatenation' },
    { pattern: /\.exec\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'Database exec with concatenation' },
    { pattern: /\.raw\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'Raw SQL query with concatenation' },
    
    // ORM unsafe patterns
    { pattern: /\.where\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'ORM where clause with concatenation' },
    { pattern: /\.whereRaw\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'ORM raw where with concatenation' }
  ];

  private readonly safePatterns = [
    // Parameterized queries
    /\?\s*,/g,  // Question mark parameters
    /\$\d+/g,   // Numbered parameters
    /:\w+/g,    // Named parameters
    /prepare/i,
    /bind/i,
    /params/i,
    /placeholder/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    for (const { pattern, type } of this.sqlInjectionPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        // Skip if the line contains safe parameterization patterns
        if (this.hasSafeParameterization(lineContent)) {
          continue;
        }

        // Skip if it's in a comment or test file
        if (this.isCommentOrTest(lineContent, fileContent.path)) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Potential SQL injection vulnerability: ${type}`,
          `Use parameterized queries or prepared statements instead of string concatenation. Replace concatenation with placeholders (?, $1, :param) and pass values as parameters.`
        ));
      }
    }

    return issues;
  }

  private hasSafeParameterization(line: string): boolean {
    return this.safePatterns.some(pattern => pattern.test(line));
  }

  private isCommentOrTest(line: string, filePath: string): boolean {
    // Check if line is a comment
    const commentPatterns = [
      /^\s*\/\//,  // JavaScript comment
      /^\s*#/,     // Python/Shell comment
      /^\s*--/,    // SQL comment
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
} 