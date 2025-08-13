import { BaseRule, FileContent, SecurityIssue } from '../types';

interface SecurityHeadersContext {
  isInComment: boolean;
  isInString: boolean;
  isInConfiguration: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  hasServerCode: boolean;
  hasSecurityHeaders: boolean;
  configurationType: string | undefined;
}

export class MissingSecurityHeadersRule extends BaseRule {
  readonly name = 'missing-security-headers';
  readonly description = 'Detects missing HTTP security headers with context-aware analysis';
  readonly severity = 'medium' as const;

  private readonly securityHeaders = [
    { 
      name: 'Content-Security-Policy',
      confidence: 0.9,
      validation: (content: string) => this.validateCSP(content),
      suggestion: 'Implement Content-Security-Policy to prevent XSS attacks'
    },
    { 
      name: 'X-Frame-Options',
      confidence: 0.85,
      validation: (content: string) => this.validateXFrameOptions(content),
      suggestion: 'Set X-Frame-Options to prevent clickjacking attacks'
    },
    { 
      name: 'X-Content-Type-Options',
      confidence: 0.8,
      validation: (content: string) => this.validateXContentTypeOptions(content),
      suggestion: 'Set X-Content-Type-Options to nosniff to prevent MIME type sniffing'
    },
    { 
      name: 'X-XSS-Protection',
      confidence: 0.7,
      validation: (content: string) => this.validateXXSSProtection(content),
      suggestion: 'Enable X-XSS-Protection for additional XSS protection'
    },
    { 
      name: 'Strict-Transport-Security',
      confidence: 0.9,
      validation: (content: string) => this.validateHSTS(content),
      suggestion: 'Implement HSTS to enforce HTTPS connections'
    },
    { 
      name: 'Referrer-Policy',
      confidence: 0.75,
      validation: (content: string) => this.validateReferrerPolicy(content),
      suggestion: 'Set Referrer-Policy to control referrer information'
    },
    { 
      name: 'Permissions-Policy',
      confidence: 0.8,
      validation: (content: string) => this.validatePermissionsPolicy(content),
      suggestion: 'Implement Permissions-Policy to control browser features'
    },
    { 
      name: 'X-Permitted-Cross-Domain-Policies',
      confidence: 0.6,
      validation: (content: string) => this.validateXPermittedCrossDomainPolicies(content),
      suggestion: 'Set X-Permitted-Cross-Domain-Policies to control cross-domain access'
    }
  ];

  private readonly serverPatterns = [
    // Express.js patterns
    { 
      pattern: /app\.(?:get|post|put|delete|patch|use)\s*\(/gi, 
      type: 'Express route handler',
      confidence: 0.9,
      validation: (text: string) => this.validateExpressPattern(text)
    },
    { 
      pattern: /router\.(?:get|post|put|delete|patch|use)\s*\(/gi, 
      type: 'Express router',
      confidence: 0.9,
      validation: (text: string) => this.validateExpressPattern(text)
    },
    { 
      pattern: /app\.listen\s*\(/gi, 
      type: 'Express server',
      confidence: 0.95,
      validation: (text: string) => this.validateExpressPattern(text)
    },
    
    // Next.js API routes
    { 
      pattern: /export\s+(?:default\s+)?(?:async\s+)?function\s+handler/gi, 
      type: 'Next.js API handler',
      confidence: 0.85,
      validation: (text: string) => this.validateNextJSPattern(text)
    },
    { 
      pattern: /export\s+(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\([^)]*req[^)]*res[^)]*\)/gi, 
      type: 'Next.js API function',
      confidence: 0.85,
      validation: (text: string) => this.validateNextJSPattern(text)
    },
    
    // Node.js HTTP server
    { 
      pattern: /createServer\s*\(\s*(?:async\s+)?\([^)]*req[^)]*res[^)]*\)/gi, 
      type: 'Node.js HTTP server',
      confidence: 0.9,
      validation: (text: string) => this.validateNodeJSPattern(text)
    },
    { 
      pattern: /http\.createServer/gi, 
      type: 'HTTP server creation',
      confidence: 0.9,
      validation: (text: string) => this.validateNodeJSPattern(text)
    },
    
    // Framework response patterns
    { 
      pattern: /res\.(?:send|json|render|redirect)/gi, 
      type: 'Response method',
      confidence: 0.8,
      validation: (text: string) => this.validateResponsePattern(text)
    },
    { 
      pattern: /response\.(?:send|json|render|redirect)/gi, 
      type: 'Response method',
      confidence: 0.8,
      validation: (text: string) => this.validateResponsePattern(text)
    },
    
    // Flask patterns
    { 
      pattern: /@app\.route/gi, 
      type: 'Flask route',
      confidence: 0.9,
      validation: (text: string) => this.validateFlaskPattern(text)
    },
    { 
      pattern: /return\s+(?:render_template|jsonify|redirect)/gi, 
      type: 'Flask response',
      confidence: 0.8,
      validation: (text: string) => this.validateFlaskPattern(text)
    },
    
    // Django patterns
    { 
      pattern: /def\s+\w+\s*\([^)]*request[^)]*\)/gi, 
      type: 'Django view function',
      confidence: 0.9,
      validation: (text: string) => this.validateDjangoPattern(text)
    },
    { 
      pattern: /HttpResponse\s*\(/gi, 
      type: 'Django HTTP response',
      confidence: 0.8,
      validation: (text: string) => this.validateDjangoPattern(text)
    },
    
    // PHP patterns
    { 
      pattern: /header\s*\(\s*['"`][^'"`]*['"`]/gi, 
      type: 'PHP header function',
      confidence: 0.85,
      validation: (text: string) => this.validatePHPPattern(text)
    }
  ];

  private readonly safePatterns = [
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
    /secure/i,
    /safe/i,
    /protected/i,
    /defense/i,
    /guard/i,
    /prevent/i,
    /block/i,
    /restrict/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const configurationType = this.detectConfigurationType(fileContent.path);
    const hasServerCode = this.hasServerCode(fileContent.content);
    const hasSecurityHeaders = this.hasSecurityHeaders(fileContent.content);
    
    // Skip if no server code detected and not a configuration file
    if (!hasServerCode && !configurationType) {
      return issues;
    }
    
    // Check for missing security headers
    const missingHeaders = this.checkMissingHeaders(fileContent);
    
    if (missingHeaders.length > 0) {
      const location = this.findReportLocation(fileContent);
      
      if (location) {
        const context = this.analyzeContext(fileContent, location.line, location.column, language, framework, hasServerCode, hasSecurityHeaders, configurationType);
        
        // Skip if in safe context to prevent false positives
        if (!this.isSafeContext(context)) {
          const finalConfidence = this.calculateConfidence(missingHeaders, context);
          
          if (finalConfidence >= 0.5) {
            issues.push(this.createIssue(
              fileContent.path,
              location.line,
              location.column,
              location.lineContent,
              `Missing security headers: ${missingHeaders.map(h => h.name).join(', ')} (confidence: ${Math.round(finalConfidence * 100)}%)`,
              this.generateSuggestion(missingHeaders, context),
              finalConfidence >= 0.8 ? 'high' : finalConfidence >= 0.6 ? 'medium' : 'low'
            ));
          }
        }
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, hasServerCode?: boolean, hasSecurityHeaders?: boolean, configurationType?: string): SecurityHeadersContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language),
      isInString: this.isInString(currentLine, column),
      isInConfiguration: this.isInConfiguration(surroundingLines),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      hasServerCode: hasServerCode || false,
      hasSecurityHeaders: hasSecurityHeaders || false,
      configurationType
    };
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
    if (language === 'yaml' || language === 'yml') {
      return trimmed.startsWith('#');
    }
    if (language === 'ini') {
      return trimmed.startsWith(';') || trimmed.startsWith('#');
    }
    return false;
  }

  private isInString(line: string, column: number): boolean {
    const before = line.substring(0, column);
    const quotes = (before.match(/['"`]/g) || []).length;
    return quotes % 2 === 1;
  }

  private isInConfiguration(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('=') || 
      line.includes(':') || 
      line.includes('[') || 
      line.includes('{')
    );
  }

  private isInTestFile(filePath: string): boolean {
    return filePath.includes('test') || filePath.includes('spec') || filePath.includes('mock');
  }

  private isInDocumentation(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('@example') || 
      line.includes('@doc') || 
      line.includes('@description') ||
      line.includes('README') ||
      line.includes('documentation')
    );
  }

  private isSafeContext(context: SecurityHeadersContext): boolean {
    // Safe if in comment
    if (context.isInComment) return true;
    
    // Safe if in test file
    if (context.isInTestFile) return true;
    
    // Safe if in documentation
    if (context.isInDocumentation) return true;
    
    // Safe if using security-related keywords
    if (this.safePatterns.some(pattern => pattern.test(context.surroundingCode))) {
      return true;
    }
    
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
      'hs': 'haskell',
      'yaml': 'yaml',
      'yml': 'yaml',
      'json': 'json',
      'ini': 'ini',
      'conf': 'conf',
      'toml': 'toml',
      'env': 'env'
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

  private detectConfigurationType(filePath: string): string | undefined {
    const configPatterns = [
      /\.conf$/i,
      /\.config$/i,
      /\.ini$/i,
      /\.yaml$/i,
      /\.yml$/i,
      /\.json$/i,
      /\.toml$/i,
      /\.env$/i,
      /\.properties$/i,
      /config\./i,
      /settings\./i
    ];
    
    for (const pattern of configPatterns) {
      if (pattern.test(filePath)) {
        const ext = filePath.split('.').pop()?.toLowerCase();
        return ext || 'unknown';
      }
    }
    return undefined;
  }

  private hasServerCode(content: string): boolean {
    return this.serverPatterns.some(({ pattern }) => pattern.test(content));
  }

  private hasSecurityHeaders(content: string): boolean {
    return this.securityHeaders.some(header => this.hasSecurityHeader(content, header.name));
  }

  private checkMissingHeaders(fileContent: FileContent): Array<{ name: string; confidence: number; suggestion: string }> {
    const missingHeaders: Array<{ name: string; confidence: number; suggestion: string }> = [];
    
    for (const header of this.securityHeaders) {
      if (!this.hasSecurityHeader(fileContent.content, header.name)) {
        missingHeaders.push(header);
      }
    }
    
    return missingHeaders;
  }

  private hasSecurityHeader(content: string, header: string): boolean {
    const headerPatterns = [
      // Express.js patterns
      new RegExp(`res\\.(?:set|header)\\s*\\(\\s*['"\`]${header}['"\`]`, 'gi'),
      new RegExp(`res\\.setHeader\\s*\\(\\s*['"\`]${header}['"\`]`, 'gi'),
      
      // Helmet.js patterns
      /helmet\s*\(\s*\)/gi,
      /helmet\./gi,
      
      // Manual header setting
      new RegExp(`['"\`]${header}['"\`]\\s*:\\s*['"\`]`, 'gi'),
      
      // PHP patterns
      new RegExp(`header\\s*\\(\\s*['"\`]${header}:`, 'gi'),
      
      // Python Flask patterns
      new RegExp(`response\\.headers\\[['"\`]${header}['"\`]\\]`, 'gi'),
      
      // Django patterns
      new RegExp(`response\\[['"\`]${header}['"\`]\\]`, 'gi'),
      
      // Configuration patterns
      new RegExp(`${header}\\s*[:=]`, 'gi')
    ];

    return headerPatterns.some(pattern => pattern.test(content));
  }

  private findReportLocation(fileContent: FileContent): { line: number; column: number; lineContent: string } | null {
    for (const { pattern } of this.serverPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      if (matches.length > 0) {
        const firstMatch = matches[0];
        if (firstMatch) {
          return {
            line: firstMatch.line,
            column: firstMatch.column,
            lineContent: firstMatch.lineContent
          };
        }
      }
    }
    return null;
  }

  private calculateConfidence(missingHeaders: Array<{ name: string; confidence: number; suggestion: string }>, context: SecurityHeadersContext): number {
    if (missingHeaders.length === 0) return 0;
    
    // Base confidence is average of missing headers
    let confidence = missingHeaders.reduce((sum, header) => sum + header.confidence, 0) / missingHeaders.length;
    
    // Adjust based on context
    if (context.hasServerCode) confidence *= 1.2; // Increase for server code
    if (context.configurationType) confidence *= 1.1; // Increase for config files
    if (context.framework) confidence *= 1.1; // Increase for known frameworks
    
    return Math.min(confidence, 1.0);
  }

  // Validation methods for different security headers
  private validateCSP(content: string): boolean {
    return /Content-Security-Policy/i.test(content);
  }

  private validateXFrameOptions(content: string): boolean {
    return /X-Frame-Options/i.test(content);
  }

  private validateXContentTypeOptions(content: string): boolean {
    return /X-Content-Type-Options/i.test(content);
  }

  private validateXXSSProtection(content: string): boolean {
    return /X-XSS-Protection/i.test(content);
  }

  private validateHSTS(content: string): boolean {
    return /Strict-Transport-Security/i.test(content);
  }

  private validateReferrerPolicy(content: string): boolean {
    return /Referrer-Policy/i.test(content);
  }

  private validatePermissionsPolicy(content: string): boolean {
    return /Permissions-Policy/i.test(content);
  }

  private validateXPermittedCrossDomainPolicies(content: string): boolean {
    return /X-Permitted-Cross-Domain-Policies/i.test(content);
  }

  // Validation methods for server patterns
  private validateExpressPattern(text: string): boolean {
    return /express/i.test(text) || /app\./i.test(text) || /router\./i.test(text);
  }

  private validateNextJSPattern(text: string): boolean {
    return /next/i.test(text) || /handler/i.test(text);
  }

  private validateNodeJSPattern(text: string): boolean {
    return /http/i.test(text) || /createServer/i.test(text);
  }

  private validateResponsePattern(text: string): boolean {
    return /res\./i.test(text) || /response\./i.test(text);
  }

  private validateFlaskPattern(text: string): boolean {
    return /flask/i.test(text) || /@app\.route/i.test(text);
  }

  private validateDjangoPattern(text: string): boolean {
    return /django/i.test(text) || /HttpResponse/i.test(text);
  }

  private validatePHPPattern(text: string): boolean {
    return /php/i.test(text) || /header\s*\(/i.test(text);
  }

  private generateSuggestion(missingHeaders: Array<{ name: string; confidence: number; suggestion: string }>, context: SecurityHeadersContext): string {
    const suggestions = missingHeaders.map(header => header.suggestion);
    let suggestion = suggestions.join('. ') + '.';
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, consider using framework-specific security middleware.`;
      
      if (context.framework === 'express') {
        suggestion += ' Use helmet.js: npm install helmet && app.use(helmet())';
      } else if (context.framework === 'flask') {
        suggestion += ' Use Flask-Talisman: pip install flask-talisman';
      } else if (context.framework === 'django') {
        suggestion += ' Configure security middleware in settings.py';
      }
    }
    
    if (context.configurationType) {
      suggestion += ` For ${context.configurationType} configuration files, ensure proper file permissions and use secure configuration management.`;
    }
    
    return suggestion;
  }
} 