import { BaseRule, FileContent, SecurityIssue } from '../types';

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

export class SqlInjectionRule extends BaseRule {
  readonly name = 'sql-injection';
  readonly description = 'Detects potential SQL injection vulnerabilities with context-aware analysis';
  readonly severity = 'high' as const;

  private readonly sqlInjectionPatterns = [
    // High confidence - Direct string concatenation
    { 
      pattern: /(?:query|sql|execute)\s*\(\s*['"`][^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, 
      type: 'String concatenation in SQL query',
      confidence: 0.95,
      validation: (text: string) => this.validateStringConcatenation(text)
    },
    { 
      pattern: /['"`](?:SELECT|INSERT|UPDATE|DELETE)\s+[^'"`]*['"`]\s*\+\s*[^'"`\s)]+/gi, 
      type: 'SQL statement with concatenation',
      confidence: 0.9,
      validation: (text: string) => this.validateSqlStatement(text)
    },
    
    // Medium confidence - Template literals with user input
    { 
      pattern: /`(?:SELECT|INSERT|UPDATE|DELETE)\s+[^`]*\$\{[^}]+\}[^`]*`/gi, 
      type: 'Template literal SQL with variables',
      confidence: 0.8,
      validation: (text: string) => this.validateTemplateLiteral(text)
    },
    { 
      pattern: /db\.query\s*\(\s*['"`][^'"`]*\$\{[^}]+\}[^'"`]*['"`]/gi, 
      type: 'Database query with template literals',
      confidence: 0.75,
      validation: (text: string) => this.validateDatabaseQuery(text)
    },
    
    // Lower confidence - Complex patterns that might be safe
    { 
      pattern: /\.where\s*\(\s*['"`][^'"`]*['"`]\s*\+/gi, 
      type: 'ORM where clause with concatenation',
      confidence: 0.6,
      validation: (text: string) => this.validateORMQuery(text)
    },
    { 
      pattern: /WHERE\s+[^'"`\s]+\s*=\s*['"`]?\s*\+\s*[^'"`\s)]+/gi, 
      type: 'WHERE clause with concatenation',
      confidence: 0.7,
      validation: (text: string) => this.validateWhereClause(text)
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
    
    for (const { pattern, type, confidence, validation } of this.sqlInjectionPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework);
        
        // Skip if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validate the pattern
        if (!validation(matchedText)) {
          continue;
        }
        
        // Calculate final confidence based on context
        const finalConfidence = this.calculateConfidence(confidence, context);
        
        if (finalConfidence >= 0.5) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `Potential SQL injection: ${type} (confidence: ${Math.round(finalConfidence * 100)}%)`,
            this.generateSuggestion(type, context),
            finalConfidence >= 0.8 ? 'high' : 'medium'
          ));
        }
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

  private isSafeContext(context: SqlInjectionContext): boolean {
    // Safe if in comment
    if (context.isInComment) return true;
    
    // Safe if in test file
    if (context.isInTestFile) return true;
    
    // Safe if in documentation
    if (context.isInDocumentation) return true;
    
    // Safe if in migration file
    if (context.isInMigration) return true;
    
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

  private calculateConfidence(baseConfidence: number, context: SqlInjectionContext): number {
    let confidence = baseConfidence;
    
    // Reduce confidence for certain contexts
    if (context.isORMUsage) confidence *= 0.7;
    if (context.framework) confidence *= 0.9; // Framework might have built-in protection
    
    return Math.min(confidence, 1.0);
  }

  // Validation methods
  private validateStringConcatenation(text: string): boolean {
    return text.includes('+') && (text.includes('req.') || text.includes('request.') || text.includes('input.'));
  }

  private validateSqlStatement(text: string): boolean {
    return /(SELECT|INSERT|UPDATE|DELETE)/i.test(text) && text.includes('+');
  }

  private validateTemplateLiteral(text: string): boolean {
    return text.includes('${') && (text.includes('req.') || text.includes('request.') || text.includes('input.'));
  }

  private validateDatabaseQuery(text: string): boolean {
    return text.includes('${') && text.includes('db.');
  }

  private validateORMQuery(text: string): boolean {
    return text.includes('+') && text.includes('.where');
  }

  private validateWhereClause(text: string): boolean {
    return text.includes('WHERE') && text.includes('+');
  }

  private generateSuggestion(_type: string, context: SqlInjectionContext): string {
    const baseSuggestion = 'Use parameterized queries or prepared statements instead of string concatenation.';
    
    if (context.framework) {
      const frameworkSuggestions = {
        'sequelize': 'Use Sequelize parameterized queries: Model.findOne({ where: { id: req.params.id } })',
        'prisma': 'Use Prisma parameterized queries: prisma.user.findFirst({ where: { id: req.params.id } })',
        'typeorm': 'Use TypeORM parameterized queries: repository.findOne({ where: { id: req.params.id } })',
        'mongoose': 'Use Mongoose parameterized queries: User.findOne({ _id: req.params.id })',
        'sqlalchemy': 'Use SQLAlchemy parameterized queries: session.query(User).filter(User.id == user_id)',
        'django': 'Use Django ORM: User.objects.filter(id=user_id)'
      };
      
      const frameworkSuggestion = frameworkSuggestions[context.framework as keyof typeof frameworkSuggestions];
      return `${baseSuggestion} ${frameworkSuggestion}`;
    }
    
    return `${baseSuggestion} Replace concatenation with placeholders (?, $1, :param) and pass values as parameters.`;
  }
} 