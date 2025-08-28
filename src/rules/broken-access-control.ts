import { BaseRule, FileContent, SecurityIssue } from '../types';

interface AccessControlContext {
  isInComment: boolean;
  isInString: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  isInDevelopment: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  hasAuthorizationChecks: boolean;
  hasAuthentication: boolean;
  isProtectedRoute: boolean;
  issueType: string | undefined;
}

export class BrokenAccessControlRule extends BaseRule {
  readonly name = 'broken-access-control';
  readonly description = 'Detects missing authorization checks and insecure direct object references with context-aware analysis';
  readonly severity = 'high' as const;

  private readonly accessControlPatterns = [
    // Missing authorization checks in routes: Tighter patterns
    { 
      pattern: /app\.(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"`]*\/(?:admin|user|api|dashboard|settings|profile|account|billing|payment|order)[^'"`]*['"`]\s*,\s*(?!.*(?:auth|login|verify|middleware|authorize|permission|guard|protect))/gi, 
      type: 'Protected route without authorization',
      confidence: 0.9,
      severity: 'high' as const,
      validation: (text: string) => this.validateProtectedRoute(text)
    },
    
    // Direct object references without ownership checks: Tighter patterns
    { 
      pattern: /findById\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^)]*\)/gi, 
      type: 'Direct object reference without ownership check',
      confidence: 0.85,
      severity: 'high' as const,
      validation: (text: string) => this.validateDirectObjectReference(text)
    },
    { 
      pattern: /findOne\s*\(\s*\{[^}]*id\s*:\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^}]*\}/gi, 
      type: 'Database query without ownership check',
      confidence: 0.8,
      severity: 'high' as const,
      validation: (text: string) => this.validateDatabaseQuery(text)
    },
    { 
      pattern: /find\s*\(\s*\{[^}]*_id\s*:\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^}]*\}/gi, 
      type: 'MongoDB query without ownership check',
      confidence: 0.8,
      severity: 'high' as const,
      validation: (text: string) => this.validateMongoDBQuery(text)
    },
    { 
      pattern: /where\s*\(\s*['"`]id['"`]\s*,\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, 
      type: 'ORM query without ownership check',
      confidence: 0.8,
      severity: 'high' as const,
      validation: (text: string) => this.validateORMQuery(text)
    },
    
    // File access without authorization: Tighter patterns
    { 
      pattern: /readFile\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^)]*\)/gi, 
      type: 'File access without authorization',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateFileAccess(text)
    },
    { 
      pattern: /writeFile\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^)]*\)/gi, 
      type: 'File write without authorization',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateFileWrite(text)
    },
    { 
      pattern: /unlink\s*\(\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^)]*\)/gi, 
      type: 'File deletion without authorization',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateFileDeletion(text)
    },
    
    // Database operations without user context: Tighter patterns
    { 
      pattern: /\.update\s*\(\s*\{[^}]*\},\s*\{[^}]*id\s*:\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^}]*\}/gi, 
      type: 'Database update without user context',
      confidence: 0.85,
      severity: 'high' as const,
      validation: (text: string) => this.validateDatabaseUpdate(text)
    },
    { 
      pattern: /\.delete\s*\(\s*\{[^}]*id\s*:\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^}]*\}/gi, 
      type: 'Database deletion without user context',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateDatabaseDeletion(text)
    },
    { 
      pattern: /\.remove\s*\(\s*\{[^}]*_id\s*:\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)[^}]*\}/gi, 
      type: 'MongoDB removal without user context',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateMongoDBRemoval(text)
    },
    
    // Role-based access control missing: Tighter patterns
    { 
      pattern: /(?:admin|user|role)\s*[:=]\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, 
      type: 'Role assignment from user input',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateRoleAssignment(text)
    },
    { 
      pattern: /(?:permission|access)\s*[:=]\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, 
      type: 'Permission assignment from user input',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validatePermissionAssignment(text)
    },
    
    // Session manipulation: Tighter patterns
    { 
      pattern: /req\.session\.(?:user|role|admin)\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, 
      type: 'Session manipulation with user input',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateSessionManipulation(text)
    },
    { 
      pattern: /session\[(?:user|role|admin)\]\s*=\s*(?:req\.|request\.|input\.|params\.|query\.|body\.)/gi, 
      type: 'Session assignment with user input',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateSessionAssignment(text)
    },
    
    // PHP patterns: Tighter patterns
    { 
      pattern: /\$_SESSION\[(?:user|role|admin)\]\s*=\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, 
      type: 'PHP session manipulation with user input',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validatePHPSessionManipulation(text)
    },
    { 
      pattern: /SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+id\s*=\s*(?:\$_GET|\$_POST|\$_REQUEST)/gi, 
      type: 'PHP database query without authorization',
      confidence: 0.9,
      severity: 'high' as const,
      validation: (text: string) => this.validatePHPDatabaseQuery(text)
    },
    
    // Python patterns: Tighter patterns
    { 
      pattern: /session\[(?:user|role|admin)\]\s*=\s*(?:request\.|flask\.request\.)/gi, 
      type: 'Python session manipulation with user input',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validatePythonSessionManipulation(text)
    },
    { 
      pattern: /User\.query\.filter_by\(id\s*=\s*(?:request\.|flask\.request\.)/gi, 
      type: 'Python ORM query without authorization',
      confidence: 0.9,
      severity: 'high' as const,
      validation: (text: string) => this.validatePythonORMQuery(text)
    },
    
    // Java patterns: Tighter patterns
    { 
      pattern: /session\.setAttribute\s*\(\s*['"`](?:user|role|admin)['"`]\s*,\s*(?:request\.getParameter|request\.getAttribute)/gi, 
      type: 'Java session manipulation with user input',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateJavaSessionManipulation(text)
    },
    { 
      pattern: /userRepository\.findById\s*\(\s*(?:request\.getParameter|request\.getAttribute)/gi, 
      type: 'Java repository query without authorization',
      confidence: 0.9,
      severity: 'high' as const,
      validation: (text: string) => this.validateJavaRepositoryQuery(text)
    }
  ];

  // Multi line comment patterns!
  private readonly multiLineCommentPatterns = [
    /\/\*[\s\S]*?\*\//g,  // JavaScript/TypeScript multi-line comments
    /""".*?"""/gs,        // Python docstrings
    /<!--.*?-->/gs,       // HTML comments
    /#\[\[.*?\]\]/gs,     // Lua multi-line comments
    /\/\*[\s\S]*?\*\//g,  // C/C++ multi-line comments
    /\/\*[\s\S]*?\*\//g   // Java multi-line comments
  ];

  private readonly authorizationPatterns = [
    // Specific authorization check patterns: Only match actual middleware/auth calls
    /auth\s*\(/i,
    /authorize\s*\(/i,
    /permission\s*\(/i,
    /role\s*\(/i,
    /admin\s*\(/i,
    /user\s*\(/i,
    /owner\s*\(/i,
    /belongsTo\s*\(/i,
    /canAccess\s*\(/i,
    /hasPermission\s*\(/i,
    /isAuthorized\s*\(/i,
    /checkAccess\s*\(/i,
    /validateAccess\s*\(/i,
    /verifyOwnership\s*\(/i,
    /ensureOwnership\s*\(/i,
    /middleware\s*\(/i,
    /guard\s*\(/i,
    /protect\s*\(/i,
    /secure\s*\(/i,
    /authorized\s*\(/i,
    /authenticated\s*\(/i,
    /loggedIn\s*\(/i,
    /session\s*\(/i,
    /token\s*\(/i,
    /jwt\s*\(/i
  ];

  private readonly falsePositivePatterns = [
    // Development and testing patterns:
    /example/i,
    /demo/i,
    /test/i,
    /sample/i,
    /placeholder/i,
    /development/i,
    /dev/i,
    /staging/i,
    /localhost/i,
    /127\.0\.0\.1/i,
    /console\.log/i,
    /console\.warn/i,
    /console\.error/i,
    /logger\.(?:log|warn|error|info)/i,
    /print/i,
    /echo/i,
    /printf/i,
    /System\.out\.println/i,
    /puts/i,
    /Console\.WriteLine/i,
    /comment/i,
    /note/i,
    /todo/i,
    /fixme/i,
    
    // Documentation and examples:
    /documentation/i,
    /docs?/i,
    /readme/i,
    /example[_-]?code/i,
    /sample[_-]?code/i,
    /demo[_-]?code/i,
    /tutorial/i,
    /guide/i,
    
    // Test files and directories:
    /test[_-]?files?/i,
    /test[_-]?data/i,
    /test[_-]?cases/i,
    /spec[_-]?files?/i,
    /__tests__/i,
    /\.test\./i,
    /\.spec\./i,
    
    // Configuration and setup:
    /config[_-]?example/i,
    /setup[_-]?example/i,
    /template[_-]?example/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const hasAuthorizationChecks = this.hasAuthorizationChecks(fileContent.content);
    const hasAuthentication = this.hasAuthentication(fileContent.content);
    const isProtectedRoute = this.isProtectedRoute(fileContent.content);
    
    for (const { pattern, type, confidence, severity, validation } of this.accessControlPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework, hasAuthorizationChecks, hasAuthentication, isProtectedRoute, type);
        
        // Skips if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validates the access control issue
        if (!validation(matchedText)) {
          continue;
        }
        
        // Calculates final confidence and severity based on context
        const finalConfidence = this.calculateConfidence(confidence, context);
        const finalSeverity = this.calculateSeverity(severity, context);
        
        if (finalConfidence >= 0.5) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `${finalSeverity.toUpperCase()}: ${type} detected (confidence: ${Math.round(finalConfidence * 100)}%): ${this.getLineContext(lineContent, column)}`,
            this.generateSuggestion(type, context),
            finalSeverity
          ));
        }
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, hasAuthorizationChecks?: boolean, hasAuthentication?: boolean, isProtectedRoute?: boolean, issueType?: string): AccessControlContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language, fileContent.content, line),
      isInString: this.isInString(currentLine, column),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(fileContent.path),
      isInDevelopment: this.isInDevelopment(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      hasAuthorizationChecks: hasAuthorizationChecks || false,
      hasAuthentication: hasAuthentication || false,
      isProtectedRoute: isProtectedRoute || false,
      issueType
    };
  }

  private isSafeContext(context: AccessControlContext): boolean {

    if (context.isInComment) return true;
    
    if (context.isInTestFile) return true;
    
    if (context.isInDocumentation) return true;
    
    if (context.isInDevelopment) return true;
    
    if (this.falsePositivePatterns.some(pattern => pattern.test(context.surroundingCode))) {
      return true;
    }
    
    return false;
  }

  private isInComment(line: string, language: string, fullContent: string, lineNumber: number): boolean {
    const trimmed = line.trim();
    
    // Checks for single line comments
    if (language === 'javascript' || language === 'typescript') {
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return true;
    }
    if (language === 'python') {
      if (trimmed.startsWith('#')) return true;
    }
    if (language === 'php') {
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('#')) return true;
    }
    
    // Checks for multi line comments
    const beforeContent = fullContent.split('\n').slice(0, lineNumber).join('\n');
    
    for (const pattern of this.multiLineCommentPatterns) {
      const matches = beforeContent.match(pattern);
      if (matches && matches.length > 0) {
        // Checks if the current line is within a multi line comment
        const lastMatch = matches[matches.length - 1];
        if (lastMatch) {
          const lastMatchIndex = beforeContent.lastIndexOf(lastMatch);
          const commentEndIndex = lastMatchIndex + lastMatch.length;
          
          // If we're still within the comment, returns true
          if (commentEndIndex >= beforeContent.length) {
            return true;
          }
        }
      }
    }
    
    return false;
  }

  private isInTestFile(filePath: string): boolean {
    return filePath.includes('test') || 
           filePath.includes('spec') || 
           filePath.includes('__tests__') ||
           filePath.match(/\.(test|spec)\./i) !== null;
  }

  private isInDocumentation(filePath: string): boolean {
    const docPatterns = [
      /docs?\//i,
      /documentation/i,
      /examples?/i,
      /samples?/i,
      /tutorials?/i,
      /guides?/i,
      /readme/i,
      /\.md$/i,
      /\.rst$/i,
      /\.txt$/i
    ];
    return docPatterns.some(pattern => pattern.test(filePath));
  }

  private isInDevelopment(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('development') || 
      line.includes('dev') ||
      line.includes('staging') ||
      line.includes('localhost') ||
      line.includes('127.0.0.1') ||
      line.includes('NODE_ENV') ||
      line.includes('DEBUG')
    );
  }

  private hasAuthorizationChecks(content: string): boolean {
    return this.authorizationPatterns.some(pattern => pattern.test(content));
  }

  private hasAuthentication(content: string): boolean {
    const authPatterns = [
      /auth\s*\(/i,
      /login\s*\(/i,
      /authenticate\s*\(/i,
      /session\s*\(/i,
      /token\s*\(/i,
      /jwt\s*\(/i
    ];
    return authPatterns.some(pattern => pattern.test(content));
  }

  private isProtectedRoute(content: string): boolean {
    const protectedPatterns = [
      /admin/i,
      /user/i,
      /api/i,
      /dashboard/i,
      /settings/i,
      /profile/i,
      /account/i,
      /billing/i,
      /payment/i,
      /order/i
    ];
    return protectedPatterns.some(pattern => pattern.test(content));
  }

  private calculateConfidence(baseConfidence: number, context: AccessControlContext): number {
    let confidence = baseConfidence;
    
    // Adjusts confidence based on context
    if (context.hasAuthorizationChecks) confidence *= 0.6; // Reduces if auth checks present
    if (context.hasAuthentication) confidence *= 0.8; // Reduces if auth present
    if (context.framework) confidence *= 1.1; // Increases for known frameworks
    
    return Math.min(confidence, 1.0);
  }

  private calculateSeverity(baseSeverity: 'critical' | 'high' | 'medium', context: AccessControlContext): 'critical' | 'high' | 'medium' {
    let severity = baseSeverity;
    
    // Never downgrades critical issues below medium
    if (baseSeverity === 'critical') {
      if (context.hasAuthorizationChecks) severity = 'high';
      if (context.hasAuthentication) severity = 'high';
      // Keep as critical if no auth measures present
    }
    
    // Adjust other severities
    if (context.hasAuthorizationChecks) {
      if (severity === 'high') severity = 'medium';
    }
    
    return severity;
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
      'go': 'go',
      'java': 'java',
      'cs': 'csharp',
      'cpp': 'cpp',
      'c': 'c',
      'rs': 'rust',
      'kt': 'kotlin',
      'swift': 'swift',
      'dart': 'dart',
      'scala': 'scala',
      'clj': 'clojure',
      'hs': 'haskell'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectFramework(content: string, language: string): string | undefined {
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('express') || content.includes('app.get') || content.includes('app.post')) return 'express';
      if (content.includes('react') || content.includes('jsx') || content.includes('tsx')) return 'react';
      if (content.includes('vue') || content.includes('Vue.createApp')) return 'vue';
      if (content.includes('angular') || content.includes('@Component')) return 'angular';
      if (content.includes('next') || content.includes('Next.js')) return 'nextjs';
    }
    if (language === 'python') {
      if (content.includes('flask') || content.includes('Flask')) return 'flask';
      if (content.includes('django') || content.includes('Django')) return 'django';
      if (content.includes('fastapi') || content.includes('FastAPI')) return 'fastapi';
    }
    if (language === 'php') {
      if (content.includes('laravel') || content.includes('Laravel')) return 'laravel';
      if (content.includes('symfony') || content.includes('Symfony')) return 'symfony';
    }
    return undefined;
  }

  private isInString(line: string, column: number): boolean {
    const before = line.substring(0, column);
    const quotes = (before.match(/['"`]/g) || []).length;
    return quotes % 2 === 1;
  }

  // Validation methods for different access control issues!
  private validateProtectedRoute(text: string): boolean {
    const protectedKeywords = ['admin', 'user', 'api', 'dashboard', 'settings', 'profile', 'account', 'billing', 'payment', 'order'];
    return protectedKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateDirectObjectReference(text: string): boolean {
    return /findById\s*\(/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateDatabaseQuery(text: string): boolean {
    return /findOne\s*\(/.test(text) && /id\s*:/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateMongoDBQuery(text: string): boolean {
    return /find\s*\(/.test(text) && /_id\s*:/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateORMQuery(text: string): boolean {
    return /where\s*\(/.test(text) && /id/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateFileAccess(text: string): boolean {
    return /readFile\s*\(/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateFileWrite(text: string): boolean {
    return /writeFile\s*\(/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateFileDeletion(text: string): boolean {
    return /unlink\s*\(/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateDatabaseUpdate(text: string): boolean {
    return /\.update\s*\(/.test(text) && /id\s*:/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateDatabaseDeletion(text: string): boolean {
    return /\.delete\s*\(/.test(text) && /id\s*:/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateMongoDBRemoval(text: string): boolean {
    return /\.remove\s*\(/.test(text) && /_id\s*:/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateRoleAssignment(text: string): boolean {
    const roleKeywords = ['admin', 'user', 'role'];
    const inputKeywords = ['req.', 'request.', 'input.', 'params.', 'query.', 'body.'];
    return roleKeywords.some(role => text.toLowerCase().includes(role)) &&
           inputKeywords.some(input => text.toLowerCase().includes(input));
  }

  private validatePermissionAssignment(text: string): boolean {
    const permissionKeywords = ['permission', 'access'];
    const inputKeywords = ['req.', 'request.', 'input.', 'params.', 'query.', 'body.'];
    return permissionKeywords.some(permission => text.toLowerCase().includes(permission)) &&
           inputKeywords.some(input => text.toLowerCase().includes(input));
  }

  private validateSessionManipulation(text: string): boolean {
    return /req\.session\./.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validateSessionAssignment(text: string): boolean {
    return /session\[/.test(text) && /req\.|request\.|input\.|params\.|query\.|body\./.test(text);
  }

  private validatePHPSessionManipulation(text: string): boolean {
    return /\$_SESSION\[/.test(text) && /\$_GET|\$_POST|\$_REQUEST/.test(text);
  }

  private validatePHPDatabaseQuery(text: string): boolean {
    return /SELECT\s+\*\s+FROM/.test(text) && /WHERE\s+id\s*=/.test(text) && /\$_GET|\$_POST|\$_REQUEST/.test(text);
  }

  private validatePythonSessionManipulation(text: string): boolean {
    return /session\[/.test(text) && /request\.|flask\.request\./.test(text);
  }

  private validatePythonORMQuery(text: string): boolean {
    return /User\.query\.filter_by\(id\s*=/.test(text) && /request\.|flask\.request\./.test(text);
  }

  private validateJavaSessionManipulation(text: string): boolean {
    return /session\.setAttribute/.test(text) && /request\.getParameter|request\.getAttribute/.test(text);
  }

  private validateJavaRepositoryQuery(text: string): boolean {
    return /userRepository\.findById/.test(text) && /request\.getParameter|request\.getAttribute/.test(text);
  }

  private getLineContext(lineContent: string, column: number): string {
    const start = Math.max(0, column - 20);
    const end = Math.min(lineContent.length, column + 20);
    return lineContent.substring(start, end).trim();
  }

  private generateSuggestion(type: string, context: AccessControlContext): string {
    const suggestions = {
      'Protected route without authorization': 'Implement authorization middleware for protected routes. Use role-based access control (RBAC) and route guards.',
      'Direct object reference without ownership check': 'Verify user ownership before accessing resources. Use user context in queries and implement ownership validation.',
      'Database query without ownership check': 'Add ownership validation to database queries. Filter by user ID or role and implement proper access controls.',
      'MongoDB query without ownership check': 'Add ownership validation to MongoDB queries. Filter by user ID or role and implement proper access controls.',
      'ORM query without ownership check': 'Add ownership validation to ORM queries. Use user context in filters and implement proper access controls.',
      'File access without authorization': 'Implement file access controls and validate user permissions before file operations. Use secure file handling.',
      'File write without authorization': 'Implement file write controls and validate user permissions before file operations. Use secure file handling.',
      'File deletion without authorization': 'Implement file deletion controls and validate user permissions before file operations. Use secure file handling.',
      'Database update without user context': 'Add user context to database updates. Ensure users can only update their own data and implement proper validation.',
      'Database deletion without user context': 'Add user context to database deletions. Ensure users can only delete their own data and implement proper validation.',
      'MongoDB removal without user context': 'Add user context to MongoDB removals. Ensure users can only remove their own data and implement proper validation.',
      'Role assignment from user input': 'Never assign roles directly from user input. Use server-side role validation and implement proper role management.',
      'Permission assignment from user input': 'Never assign permissions directly from user input. Use server-side permission validation and implement proper permission management.',
      'Session manipulation with user input': 'Never manipulate session data with user input. Use server-side session management and implement proper session controls.',
      'Session assignment with user input': 'Never assign session data with user input. Use server-side session management and implement proper session controls.',
      'PHP session manipulation with user input': 'Never manipulate PHP session data with user input. Use server-side session management and implement proper session controls.',
      'PHP database query without authorization': 'Add authorization checks to PHP database queries. Use prepared statements and implement proper access controls.',
      'Python session manipulation with user input': 'Never manipulate Python session data with user input. Use server-side session management and implement proper session controls.',
      'Python ORM query without authorization': 'Add authorization checks to Python ORM queries. Filter by user context and implement proper access controls.',
      'Java session manipulation with user input': 'Never manipulate Java session data with user input. Use server-side session management and implement proper session controls.',
      'Java repository query without authorization': 'Add authorization checks to Java repository queries. Filter by user context and implement proper access controls.'
    };
    
    let suggestion = suggestions[type as keyof typeof suggestions] || 'Implement proper authorization checks. Verify user ownership, check roles/permissions, and ensure users can only access their own resources.';
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, consider using framework-specific authorization patterns.`;
      
      if (context.framework === 'express') {
        suggestion += ' Use express-session, passport.js, and authorization middleware.';
      } else if (context.framework === 'django') {
        suggestion += ' Use Django\'s built-in authentication and permission system.';
      } else if (context.framework === 'laravel') {
        suggestion += ' Use Laravel\'s Gates and Policies for authorization.';
      } else if (context.framework === 'react') {
        suggestion += ' Implement client-side route guards and server-side authorization.';
      }
    }
    
    // Context aware suggestions based on issue type!
    if (context.issueType?.includes('route')) {
      suggestion += ' Consider implementing route-level authorization middleware.';
    } else if (context.issueType?.includes('database') || context.issueType?.includes('query')) {
      suggestion += ' Use parameterized queries and implement data-level authorization.';
    } else if (context.issueType?.includes('session')) {
      suggestion += ' Implement secure session management and validation.';
    } else if (context.issueType?.includes('file')) {
      suggestion += ' Use secure file handling libraries and implement file-level permissions.';
    }
    
    return suggestion;
  }
} 