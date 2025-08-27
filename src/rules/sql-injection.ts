import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

interface SqlInjectionContext {
  isInComment: boolean;
  isInString: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  isInMigration: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  hasParameterizedQueries: boolean;
  isORMUsage: boolean;
}

interface SqlInjectionPattern {
  pattern: RegExp;
  type: string;
  severity: SeverityLevel;
  description: string;
  validation: (text: string) => boolean;
}

export class SqlInjectionRule extends BaseRule {
  readonly name = 'sql-injection';
  readonly description = 'Detects potential SQL injection vulnerabilities with context-aware analysis';
  readonly severity = 'high' as const;

  private readonly sqlInjectionPatterns: SqlInjectionPattern[] = [
    // Critical - Database query with raw concatenation and request input
    { 
      pattern: /\b(?:query|sql|execute|CommandText)\s*[:=]\s*['"`][^'"`]*['"`]\s*[+]\s*\b(?:req\.|request\.|input\.|form\.|queryParam\.|body\.|params\.)/gi, 
      type: 'Database query with raw concatenation and request input',
      severity: 'critical',
      description: 'Critical SQL injection risk: User input directly concatenated into database queries',
      validation: (text: string) => this.validateTaintedInput(text)
    },
    { 
      pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC)\s+[^'"`]*['"`]\s*[+]\s*\b(?:req\.|request\.|input\.|form\.|queryParam\.|body\.|params\.)/gi, 
      type: 'SQL statement with tainted input concatenation',
      severity: 'critical',
      description: 'Critical SQL injection risk: SQL statement with user input concatenation',
      validation: (text: string) => this.validateSqlStatement(text)
    },
    
    // High - Template literals and string interpolation
    { 
      pattern: /\b(?:query|sql|execute)\s*[:=]\s*`[^`]*\$\{[^}]+\}[^`]*`/gi, 
      type: 'Template literal SQL with variables',
      severity: 'high',
      description: 'High SQL injection risk: Template literals with user input in database queries',
      validation: (text: string) => this.validateTemplateLiteral(text)
    },
    { 
      pattern: /\bf["`][^`"]*\$\{[^}]*\}[^`"]*["`]/gi, 
      type: 'Python f-string SQL injection',
      severity: 'high',
      description: 'High SQL injection risk: Python f-string with user input in SQL context',
      validation: (text: string) => this.validateFStringInjection(text)
    },
    { 
      pattern: /\b(?:query|sql|execute)\s*[:=]\s*['"`][^'"`]*\{[^}]*\}[^'"`]*['"`]\.format\(/gi, 
      type: 'Python format string SQL injection',
      severity: 'high',
      description: 'High SQL injection risk: Python .format() with user input in SQL context',
      validation: (text: string) => this.validateFormatStringInjection(text)
    },
    { 
      pattern: /\b(?:query|sql|execute)\s*[:=]\s*['"`][^'"`]*%s[^'"`]*['"`]\s*%\s*\b(?:req\.|request\.|input\.|form\.|queryParam\.|body\.|params\.)/gi, 
      type: 'Python %s substitution SQL injection',
      severity: 'high',
      description: 'High SQL injection risk: Python %s substitution with user input',
      validation: (text: string) => this.validatePercentSubstitution(text)
    },
    
    // Medium - ORM concatenation and JDBC patterns
    { 
      pattern: /\b\.where\s*\(\s*['"`][^'"`]*['"`]\s*[+]\s*\b(?:req\.|request\.|input\.|form\.|queryParam\.|body\.|params\.)/gi, 
      type: 'ORM where clause with concatenation',
      severity: 'medium',
      description: 'Medium SQL injection risk: ORM where clause with user input concatenation',
      validation: (text: string) => this.validateORMQuery(text)
    },
    { 
      pattern: /\bStatement\s*\.\s*executeQuery\s*\(\s*['"`][^'"`]*['"`]\s*[+]\s*\b(?:req\.|request\.|input\.|form\.|queryParam\.|body\.|params\.)/gi, 
      type: 'Java JDBC string concatenation',
      severity: 'medium',
      description: 'Medium SQL injection risk: Java JDBC with string concatenation',
      validation: (text: string) => this.validateJDBCConcatenation(text)
    },
    { 
      pattern: /\bCommandText\s*[:=]\s*['"`][^'"`]*['"`]\s*[+]\s*\b(?:req\.|request\.|input\.|form\.|queryParam\.|body\.|params\.)/gi, 
      type: 'C# ADO.NET CommandText concatenation',
      severity: 'medium',
      description: 'Medium SQL injection risk: C# ADO.NET CommandText with string concatenation',
      validation: (text: string) => this.validateADOConcatenation(text)
    },
    
    // Low - Suspicious patterns in migrations/tests
    { 
      pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC)\s+[^'"`]*['"`]\s*[+]/gi, 
      type: 'SQL statement with concatenation',
      severity: 'low',
      description: 'Low SQL injection risk: SQL statement with concatenation (may be safe in migrations)',
      validation: (text: string) => this.validateSqlConcatenation(text)
    },
    { 
      pattern: /\b(?:query|sql|execute)\s*[:=]\s*['"`][^'"`]*['"`]\s*[+]/gi, 
      type: 'Database query with concatenation',
      severity: 'low',
      description: 'Low SQL injection risk: Database query with concatenation (may be safe in migrations)',
      validation: (text: string) => this.validateQueryConcatenation(text)
    }
  ];

  private readonly safePatterns = [
    // Parameterized queries
    /\?\s*,/g,
    /\$\d+/g,
    /:\w+/g,
    /@\w+/g,
    /prepare\s*\(/i,
    /bind\s*\(/i,
    /params\s*\[/i,
    /placeholder\s*\(/i,
    
    // ORM safe patterns
    /\.findOne\s*\(\s*\{/gi,
    /\.findAll\s*\(\s*\{/gi,
    /\.create\s*\(\s*\{/gi,
    /\.update\s*\(\s*\{/gi,
    /\.destroy\s*\(\s*\{/gi,
    
    // Query builders
    /\.select\s*\(/gi,
    /\.from\s*\(/gi,
    /\.where\s*\(\s*\{/gi,
    /\.andWhere\s*\(/gi,
    /\.orWhere\s*\(/gi
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    
    for (const { pattern, type, severity, description, validation } of this.sqlInjectionPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework);
        
        // Skip if in safe context (but not migrations - we want to flag those with lower severity)
        if (this.isSafeContext(context) && !context.isInMigration) {
          continue;
        }
        
        // Validate the pattern
        if (!validation(matchedText)) {
          continue;
        }
        
        // Determine final severity based on context
        const finalSeverity = this.determineSeverity(severity, context);
        
        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `Potential SQL injection: ${type} - ${description}`,
          this.getRemediationMessage(type, context, finalSeverity),
          finalSeverity
        ));
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string): SqlInjectionContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language),
      isInString: this.isInString(currentLine, column),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(surroundingLines),
      isInMigration: this.isInMigration(fileContent.path),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      hasParameterizedQueries: this.hasParameterizedQueries(surroundingLines),
      isORMUsage: this.isORMUsage(surroundingLines, framework)
    };
  }

  private determineSeverity(baseSeverity: SeverityLevel, context: SqlInjectionContext): SeverityLevel {
    // Downgrade severity in migration/test contexts instead of skipping
    if (context.isInMigration || context.isInTestFile) {
      switch (baseSeverity) {
        case 'critical': return 'high';
        case 'high': return 'medium';
        case 'medium': return 'low';
        case 'low': return 'low';
        default: return baseSeverity;
      }
    }
    
    return baseSeverity;
  }

  private isSafeContext(context: SqlInjectionContext): boolean {
    // Safe if in comment
    if (context.isInComment) return true;
    
    // Safe if in documentation
    if (context.isInDocumentation) return true;
    
    // Safe if using parameterized queries
    if (context.hasParameterizedQueries) return true;
    
    // Safe if using ORM properly
    if (context.isORMUsage) return true;
    
    return false;
  }

  private detectLanguage(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const languageMap: Record<string, string> = {
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'typescript',
      'tsx': 'typescript',
      'py': 'python',
      'php': 'php',
      'rb': 'ruby',
      'java': 'java',
      'cs': 'csharp'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectFramework(content: string, language: string): string | undefined {
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('sequelize') || content.includes('Sequelize')) return 'sequelize';
      if (content.includes('prisma') || content.includes('Prisma')) return 'prisma';
      if (content.includes('typeorm') || content.includes('TypeORM')) return 'typeorm';
      if (content.includes('mongoose') || content.includes('Mongoose')) return 'mongoose';
      if (content.includes('knex') || content.includes('Knex')) return 'knex';
    }
    if (language === 'python') {
      if (content.includes('sqlalchemy') || content.includes('SQLAlchemy')) return 'sqlalchemy';
      if (content.includes('django.db') || content.includes('models.Model')) return 'django';
    }
    if (language === 'java') {
      if (content.includes('hibernate') || content.includes('Hibernate')) return 'hibernate';
      if (content.includes('jpa') || content.includes('JPA')) return 'jpa';
    }
    return undefined;
  }



  private isInComment(line: string, language: string): boolean {
    const trimmed = line.trim();
    if (language === 'javascript' || language === 'typescript') {
      return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
    }
    if (language === 'python') {
      return trimmed.startsWith('#');
    }
    if (language === 'php') {
      return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('#');
    }
    return false;
  }

  private isInString(line: string, column: number): boolean {
    const before = line.substring(0, column);
    const quotes = (before.match(/['"`]/g) || []).length;
    return quotes % 2 === 1;
  }

  private isInTestFile(filePath: string): boolean {
    return filePath.includes('test') || filePath.includes('spec') || filePath.includes('mock');
  }

  private isInDocumentation(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('@example') || 
      line.includes('TODO') ||
      line.includes('FIXME') ||
      line.includes('NOTE:')
    );
  }

  private isInMigration(filePath: string): boolean {
    return filePath.includes('migration') || filePath.includes('migrate') || filePath.includes('schema');
  }

  private hasParameterizedQueries(lines: string[]): boolean {
    return lines.some(line => 
      this.safePatterns.some(pattern => pattern.test(line))
    );
  }

  private isORMUsage(lines: string[], framework?: string): boolean {
    if (!framework) return false;
    
    const ormPatterns = {
      'sequelize': /\.findOne|\.findAll|\.create|\.update|\.destroy/gi,
      'prisma': /\.findFirst|\.findMany|\.create|\.update|\.delete/gi,
      'typeorm': /\.findOne|\.find|\.save|\.remove/gi,
      'mongoose': /\.find|\.findOne|\.create|\.updateOne/gi,
      'sqlalchemy': /\.query\.|\.filter|\.filter_by/gi,
      'django': /\.objects\.|\.filter|\.get/gi
    };
    
    const pattern = ormPatterns[framework as keyof typeof ormPatterns];
    return pattern ? lines.some(line => pattern.test(line)) : false;
  }



  // Advanced validation methods for tainted input detection
  private validateTaintedInput(text: string): boolean {
    const taintedPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bform\./i,
      /\bqueryParam\./i,
      /\bbody\./i,
      /\bparams\./i
    ];
    return taintedPatterns.some(pattern => pattern.test(text)) && text.includes('+');
  }

  private validateSqlStatement(text: string): boolean {
    const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'EXEC'];
    const taintedPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bform\./i,
      /\bqueryParam\./i,
      /\bbody\./i,
      /\bparams\./i
    ];
    return sqlKeywords.some(keyword => text.toUpperCase().includes(keyword)) && 
           taintedPatterns.some(pattern => pattern.test(text)) && 
           text.includes('+');
  }

  private validateTemplateLiteral(text: string): boolean {
    const taintedPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bform\./i,
      /\bqueryParam\./i,
      /\bbody\./i,
      /\bparams\./i
    ];
    return text.includes('${') && taintedPatterns.some(pattern => pattern.test(text));
  }

  private validateFStringInjection(text: string): boolean {
    const taintedPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bform\./i,
      /\bqueryParam\./i,
      /\bbody\./i,
      /\bparams\./i
    ];
    return text.includes('f"') || text.includes("f'") && taintedPatterns.some(pattern => pattern.test(text));
  }

  private validateFormatStringInjection(text: string): boolean {
    const taintedPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bform\./i,
      /\bqueryParam\./i,
      /\bbody\./i,
      /\bparams\./i
    ];
    return text.includes('.format(') && taintedPatterns.some(pattern => pattern.test(text));
  }

  private validatePercentSubstitution(text: string): boolean {
    const taintedPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bform\./i,
      /\bqueryParam\./i,
      /\bbody\./i,
      /\bparams\./i
    ];
    return text.includes('%s') && text.includes('%') && taintedPatterns.some(pattern => pattern.test(text));
  }

  private validateORMQuery(text: string): boolean {
    const taintedPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bform\./i,
      /\bqueryParam\./i,
      /\bbody\./i,
      /\bparams\./i
    ];
    return text.includes('+') && text.includes('.where') && taintedPatterns.some(pattern => pattern.test(text));
  }

  private validateJDBCConcatenation(text: string): boolean {
    const taintedPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bform\./i,
      /\bqueryParam\./i,
      /\bbody\./i,
      /\bparams\./i
    ];
    return text.includes('Statement') && text.includes('executeQuery') && 
           taintedPatterns.some(pattern => pattern.test(text)) && text.includes('+');
  }

  private validateADOConcatenation(text: string): boolean {
    const taintedPatterns = [
      /\breq\./i,
      /\brequest\./i,
      /\binput\./i,
      /\bform\./i,
      /\bqueryParam\./i,
      /\bbody\./i,
      /\bparams\./i
    ];
    return text.includes('CommandText') && taintedPatterns.some(pattern => pattern.test(text)) && text.includes('+');
  }

  private validateSqlConcatenation(text: string): boolean {
    const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'EXEC'];
    return sqlKeywords.some(keyword => text.toUpperCase().includes(keyword)) && text.includes('+');
  }

  private validateQueryConcatenation(text: string): boolean {
    return (text.includes('query') || text.includes('sql') || text.includes('execute')) && text.includes('+');
  }

  private getRemediationMessage(type: string, context: SqlInjectionContext, severity: SeverityLevel): string {
    const messages: Record<string, Record<string, string>> = {
      'Database query with raw concatenation and request input': {
        'critical': 'CRITICAL: Never concatenate user input directly into database queries. Use parameterized queries or prepared statements. This is a severe security vulnerability.',
        'high': 'HIGH: Use parameterized queries instead of string concatenation. Replace concatenation with placeholders.',
        'medium': 'MEDIUM: Consider using parameterized queries for better security.',
        'low': 'LOW: Review query construction for potential injection vulnerabilities.'
      },
      'SQL statement with tainted input concatenation': {
        'critical': 'CRITICAL: SQL statement with user input concatenation is extremely dangerous. Use parameterized queries immediately.',
        'high': 'HIGH: Use parameterized queries instead of concatenating user input into SQL statements.',
        'medium': 'MEDIUM: Consider using parameterized queries for SQL statements.',
        'low': 'LOW: Review SQL statement construction.'
      },
      'Template literal SQL with variables': {
        'critical': 'CRITICAL: Template literals with user input in SQL are dangerous. Use parameterized queries.',
        'high': 'HIGH: Avoid template literals with user input in SQL. Use parameterized queries.',
        'medium': 'MEDIUM: Consider using parameterized queries instead of template literals.',
        'low': 'LOW: Review template literal usage in SQL.'
      },
      'Python f-string SQL injection': {
        'critical': 'CRITICAL: Never use f-strings with user input in SQL. Use parameterized queries.',
        'high': 'HIGH: Avoid f-strings with user input in SQL. Use parameterized queries.',
        'medium': 'MEDIUM: Consider using parameterized queries instead of f-strings.',
        'low': 'LOW: Review f-string usage in SQL.'
      },
      'Python format string SQL injection': {
        'critical': 'CRITICAL: Never use .format() with user input in SQL. Use parameterized queries.',
        'high': 'HIGH: Avoid .format() with user input in SQL. Use parameterized queries.',
        'medium': 'MEDIUM: Consider using parameterized queries instead of .format().',
        'low': 'LOW: Review .format() usage in SQL.'
      },
      'Python %s substitution SQL injection': {
        'critical': 'CRITICAL: Never use %s substitution with user input in SQL. Use parameterized queries.',
        'high': 'HIGH: Avoid %s substitution with user input in SQL. Use parameterized queries.',
        'medium': 'MEDIUM: Consider using parameterized queries instead of %s substitution.',
        'low': 'LOW: Review %s substitution usage in SQL.'
      },
      'ORM where clause with concatenation': {
        'critical': 'CRITICAL: ORM where clauses with user input concatenation are dangerous. Use parameterized ORM methods.',
        'high': 'HIGH: Use parameterized ORM methods instead of concatenation in where clauses.',
        'medium': 'MEDIUM: Consider using parameterized ORM methods.',
        'low': 'LOW: Review ORM where clause construction.'
      },
      'Java JDBC string concatenation': {
        'critical': 'CRITICAL: JDBC with string concatenation is dangerous. Use PreparedStatement with placeholders.',
        'high': 'HIGH: Use PreparedStatement with placeholders instead of string concatenation.',
        'medium': 'MEDIUM: Consider using PreparedStatement for JDBC queries.',
        'low': 'LOW: Review JDBC query construction.'
      },
      'C# ADO.NET CommandText concatenation': {
        'critical': 'CRITICAL: ADO.NET CommandText with concatenation is dangerous. Use parameterized queries.',
        'high': 'HIGH: Use parameterized queries instead of CommandText concatenation.',
        'medium': 'MEDIUM: Consider using parameterized queries with ADO.NET.',
        'low': 'LOW: Review ADO.NET query construction.'
      }
    };
    
    let suggestion = messages[type]?.[severity] || 'Use parameterized queries or prepared statements instead of string concatenation.';
    
    if (context.framework) {
      suggestion += this.getFrameworkSpecificAdvice(context.framework, type);
    }
    
    if (context.language) {
      suggestion += this.getLanguageSpecificAdvice(context.language, type);
    }
    
    return suggestion;
  }

  private getFrameworkSpecificAdvice(framework: string, type: string): string {
    const advice: Record<string, Record<string, string>> = {
      'sequelize': {
        'Database query with raw concatenation and request input': ' For Sequelize, use: Model.findOne({ where: { id: req.params.id } })',
        'ORM where clause with concatenation': ' For Sequelize, use parameterized where clauses: { where: { column: value } }'
      },
      'prisma': {
        'Database query with raw concatenation and request input': ' For Prisma, use: prisma.user.findFirst({ where: { id: req.params.id } })',
        'ORM where clause with concatenation': ' For Prisma, use parameterized queries: { where: { column: value } }'
      },
      'typeorm': {
        'Database query with raw concatenation and request input': ' For TypeORM, use: repository.findOne({ where: { id: req.params.id } })',
        'ORM where clause with concatenation': ' For TypeORM, use parameterized queries: { where: { column: value } }'
      },
      'sqlalchemy': {
        'Database query with raw concatenation and request input': ' For SQLAlchemy, use: session.query(User).filter(User.id == user_id)',
        'Python f-string SQL injection': ' For SQLAlchemy, use parameterized queries: session.query(User).filter(User.id == user_id)'
      },
      'django': {
        'Database query with raw concatenation and request input': ' For Django, use: User.objects.filter(id=user_id)',
        'Python format string SQL injection': ' For Django, use ORM: User.objects.filter(id=user_id)'
      }
    };
    
    return advice[framework]?.[type] || ` For ${framework}, use framework-specific parameterized query methods.`;
  }

  private getLanguageSpecificAdvice(language: string, type: string): string {
    const advice: Record<string, Record<string, string>> = {
      'python': {
        'Python f-string SQL injection': ' In Python, use parameterized queries with libraries like psycopg2, sqlite3, or ORMs.',
        'Python format string SQL injection': ' In Python, use parameterized queries with libraries like psycopg2, sqlite3, or ORMs.',
        'Python %s substitution SQL injection': ' In Python, use parameterized queries with libraries like psycopg2, sqlite3, or ORMs.'
      },
      'javascript': {
        'Template literal SQL with variables': ' In JavaScript, use parameterized queries with libraries like mysql2, pg, or ORMs.',
        'Database query with raw concatenation and request input': ' In JavaScript, use parameterized queries with libraries like mysql2, pg, or ORMs.'
      },
      'java': {
        'Java JDBC string concatenation': ' In Java, use PreparedStatement with placeholders (?) and setParameter methods.',
        'Database query with raw concatenation and request input': ' In Java, use PreparedStatement with placeholders (?) and setParameter methods.'
      },
      'csharp': {
        'C# ADO.NET CommandText concatenation': ' In C#, use SqlCommand with parameters (@param) and AddParameter methods.',
        'Database query with raw concatenation and request input': ' In C#, use SqlCommand with parameters (@param) and AddParameter methods.'
      }
    };
    
    return advice[language]?.[type] || ` In ${language}, use language-specific parameterized query methods.`;
  }
} 