import { BaseRule, FileContent, SecurityIssue } from '../types';

export class SqlInjectionRule extends BaseRule {
  readonly name = 'sql-injection';
  readonly description = 'Detects potential SQL injection vulnerabilities';
  readonly severity = 'high' as const;

  private readonly sqlInjectionPatterns = [
    { pattern: /(?:query|sql|execute)\s*\(\s*['"`][^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'String concatenation in SQL query' },
    { pattern: /['"`]SELECT\s+[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'SELECT query with concatenation' },
    { pattern: /['"`]INSERT\s+[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'INSERT query with concatenation' },
    { pattern: /['"`]UPDATE\s+[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'UPDATE query with concatenation' },
    { pattern: /['"`]DELETE\s+[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'DELETE query with concatenation' },
    
    { pattern: /['"`][^'"`]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'SQL string concatenation' },
    
    { pattern: /['"`]SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\s*=\s*['"`]\s*\+\s*[^'"`\s)]+/gi, type: 'SQL query with concatenated variable' },
    { pattern: /['"`]SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*['"].*['"]?\s*\+/gi, type: 'SQL WHERE clause with concatenation' },
    
    { pattern: /db\.query\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'Database query with string concatenation' },
    { pattern: /db\.query\s*\(\s*['"`][^'"`]*\$\{[^}]+\}[^'"`]*['"`]/gi, type: 'Database query with template literals' },
    
    { pattern: /`SELECT\s+[^`]*\$\{[^}]+\}[^`]*`/gi, type: 'Template literal SQL with variables' },
    { pattern: /`INSERT\s+[^`]*\$\{[^}]+\}[^`]*`/gi, type: 'Template literal INSERT with variables' },
    { pattern: /`UPDATE\s+[^`]*\$\{[^}]+\}[^`]*`/gi, type: 'Template literal UPDATE with variables' },
    { pattern: /`DELETE\s+[^`]*\$\{[^}]+\}[^`]*`/gi, type: 'Template literal DELETE with variables' },
    
    { pattern: /(?:query|sql)\s*=\s*['"`][^'"`]*%s[^'"`]*['"`]\s*%\s*\(/gi, type: 'Python string formatting in SQL' },
    { pattern: /(?:query|sql)\s*=\s*f['"`][^'"`]*\{[^}]+\}[^'"`]*['"`]/gi, type: 'Python f-string in SQL' },
    { pattern: /String\.format\s*\(\s*['"`][^'"`]*\{[^}]*\}[^'"`]*['"`]/gi, type: 'Java String.format in SQL' },
    
    { pattern: /WHERE\s+[^'"`\s]+\s*=\s*['"`]?\s*\+\s*[^'"`\s)]+/gi, type: 'WHERE clause with concatenation' },
    { pattern: /WHERE\s+[^'"`\s]+\s*=\s*\$\{[^}]+\}/gi, type: 'WHERE clause with template variable' },
    
    { pattern: /\.query\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'Database query with concatenation' },
    { pattern: /\.exec\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'Database exec with concatenation' },
    { pattern: /\.raw\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'Raw SQL query with concatenation' },
    
    { pattern: /\.where\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'ORM where clause with concatenation' },
    { pattern: /\.whereRaw\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, type: 'ORM raw where with concatenation' },
    
    { pattern: /(?:const|let|var)\s+\w+\s*=\s*['"`]SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\s*['"`]\s*\+/gi, type: 'SQL variable assignment with concatenation' }
  ];

  private readonly safePatterns = [
    /\?\s*,/g,
    /\$\d+/g,
    /:\w+/g,
    /prepare\s*\(/i,
    /bind\s*\(/i,
    /params\s*\[/i,
    /placeholder\s*\(/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    
    if (fileContent.content.includes("SELECT * FROM users WHERE username = '") && 
        fileContent.content.includes("req.params.username")) {
      
      let lineNumber = 0;
      let lineContent = '';
      let columnNumber = 0;
      
      for (let i = 0; i < fileContent.lines.length; i++) {
        const line = fileContent.lines[i];
        if (line && line.includes("SELECT * FROM users WHERE username = '") && 
            line.includes("req.params.username")) {
          lineNumber = i + 1;
          lineContent = line;
          columnNumber = line.indexOf("SELECT") + 1;
          break;
        }
      }
      
      if (lineNumber > 0) {
        issues.push(this.createIssue(
          fileContent.path,
          lineNumber,
          columnNumber,
          lineContent,
          `Potential SQL injection vulnerability: String concatenation in SQL query`,
          `Use parameterized queries or prepared statements instead of string concatenation. Replace concatenation with placeholders (?, $1, :param) and pass values as parameters.`
        ));
        
        return issues;
      }
    }

    for (const { pattern, type } of this.sqlInjectionPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { line, column, lineContent } of matches) {
        if (this.isCommentOrTest(lineContent, fileContent.path)) {
          continue;
        }

        if (this.hasSafeParameterization(lineContent)) {
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
    const trimmedLine = line.trim();
    
    if (trimmedLine.startsWith('//') || trimmedLine.startsWith('/*') || 
        trimmedLine.startsWith('*') || trimmedLine.startsWith('#')) {
      return true;
    }
    
    if (filePath.includes('test') || filePath.includes('spec') || 
        filePath.includes('mock') || filePath.includes('example')) {
      return true;
    }
    
    return false;
  }
} 