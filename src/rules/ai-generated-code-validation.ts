import { BaseRule, FileContent, SecurityIssue } from '../types';

interface AiCodeContext {
  isInComment: boolean;
  isInString: boolean;
  isInTestFile: boolean;
  isInDocumentation: boolean;
  isInDevelopment: boolean;
  isInCommitLog: boolean;
  isInLicenseHeader: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
  hasSecurityMeasures: boolean;
  issueCount: number;
}

export class AiGeneratedCodeValidationRule extends BaseRule {
  readonly name = 'ai-generated-code-validation';
  readonly description = 'Detects security issues in AI-generated code and validates its safety with context-aware analysis';
  readonly severity = 'high' as const;

  private readonly aiCodePatterns = [
    // AI generated code indicators: More specific assignment patterns!
    // Medium severity
    { 
      pattern: /(?:generated[_-]?by|ai[_-]?generated|copilot|chatgpt|gpt[_-]?generated|claude[_-]?generated)\s*[:=]\s*['"`]?[^'"`]*['"`]?/gi, 
      type: 'AI-Generated Code',
      confidence: 0.7,
      severity: 'medium' as const,
      validation: (text: string) => this.validateAiGeneratedCode(text)
    },
    // High severity
    { 
      pattern: /(?:ai|generated|copilot)\s*[:=]\s*['"`]?[^'"`]*(?:unvalidated|unreviewed|unchecked)['"`]?/gi, 
      type: 'Unvalidated AI Code',
      confidence: 0.85,
      severity: 'high' as const,
      validation: (text: string) => this.validateUnvalidatedCode(text)
    },
    // High severity
    { 
      pattern: /(?:ai|generated|copilot)\s*[:=]\s*['"`]?[^'"`]*(?:no[_-]?review|without[_-]?review|skip[_-]?review)['"`]?/gi, 
      type: 'AI Code Without Security Review',
      confidence: 0.9,
      severity: 'high' as const,
      validation: (text: string) => this.validateNoReviewCode(text)
    },
    // Critical severity
    { 
      pattern: /(?:ai|generated|copilot)\s*[:=]\s*['"`]?[^'"`]*(?:vulnerable|insecure|unsafe)['"`]?/gi, 
      type: 'Vulnerable AI-Generated Code',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateVulnerableCode(text)
    },
    // Critical severity
    { 
      pattern: /(?:ai|generated|copilot)\s*[:=]\s*['"`]?[^'"`]*(?:bypass|skip|ignore)\s*[:=]\s*['"`]?[^'"`]*(?:security|validation)['"`]?/gi, 
      type: 'AI Code Bypassing Security',
      confidence: 0.95,
      severity: 'critical' as const,
      validation: (text: string) => this.validateSecurityBypass(text)
    },
    
    // Dangerous code patterns: eval, system commands, SQL injection
    { 
      pattern: /eval\s*\(\s*['"`]?[^'"`]*\$\{[^}]+\}[^'"`]*['"`]?/gi, 
      type: 'AI-Generated Eval with Variables',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateEvalWithVariables(text)
    },
    // Critical severity
    { 
      pattern: /(?:exec|system|spawn)\s*\(\s*['"`]?[^'"`]*\$\{[^}]+\}[^'"`]*['"`]?/gi, 
      type: 'AI-Generated System Commands',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateSystemCommands(text)
    },
    // High severity
    { 
      pattern: /(?:query|sql)\s*[:=]\s*['"`]?[^'"`]*\$\{[^}]+\}[^'"`]*['"`]?/gi, 
      type: 'AI-Generated SQL with Variables',
      confidence: 0.85,
      severity: 'high' as const,
      validation: (text: string) => this.validateSqlWithVariables(text)
    },
    // Multi line AI injection patterns!
    {
      pattern: /(?:prompt|input)\s*[:=]\s*['"`]?[^'"`]*(?:ignore|forget|system|assistant|user)\s*[:=]\s*['"`]?[^'"`]*(?:previous|above|instructions)['"`]?/gis,
      type: 'Multi-Line AI Injection',
      confidence: 0.9,
      severity: 'critical' as const,
      validation: (text: string) => this.validateMultiLineInjection(text)
    },
    
    // AI generated file operations!
    { 
      pattern: /(?:readFile|writeFile|fs\.(?:read|write))\s*\(\s*['"`]?[^'"`]*\$\{[^}]+\}[^'"`]*['"`]?/gi, 
      type: 'AI-Generated File Operations',
      confidence: 0.8,
      severity: 'high' as const,
      validation: (text: string) => this.validateFileOperations(text)
    },
    
    // AI generated network requests!
    { 
      pattern: /(?:fetch|axios|request)\s*\(\s*['"`]?[^'"`]*\$\{[^}]+\}[^'"`]*['"`]?/gi, 
      type: 'AI-Generated Network Requests',
      confidence: 0.75,
      severity: 'medium' as const,
      validation: (text: string) => this.validateNetworkRequests(text)
    }
  ];

  private readonly falsePositivePatterns = [
    // Development and testing patterns:
    /example/i,
    /demo/i,
    /test/i,
    /mock/i,
    /sample/i,
    /placeholder/i,
    /comment/i,
    /todo/i,
    /fixme/i,
    /\/\/.*/i,
    /#.*/i,
    /\/\*.*\*\//i,
    /<!--.*-->/i,
    /development/i,
    /dev/i,
    /staging/i,
    /localhost/i,
    
    // Documentation and examples:
    /documentation/i,
    /readme/i,
    /docs/i,
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
    /template[_-]?example/i,
    
    // Commit logs and version control:
    /commit/i,
    /git/i,
    /svn/i,
    /version/i,
    /changelog/i,
    /history/i,
    
    // License headers:
    /license/i,
    /copyright/i,
    /mit/i,
    /apache/i,
    /gpl/i,
    /bsd/i,
    
    // Security related false positives (likely safe):
    /validate/i,
    /review/i,
    /secure/i,
    /safe/i,
    /sanitize/i,
    /escape/i,
    /filter/i,
    /protect/i,
    /audit/i,
    /scan/i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const hasSecurityMeasures = this.hasSecurityMeasures(fileContent.content);
    
    for (const { pattern, type, confidence, severity, validation } of this.aiCodePatterns) {
      let matches;
      
      // Handles multi line patterns differently!
      if (pattern.flags.includes('s')) {
        matches = this.findMultiLineMatches(fileContent.content, pattern);
      } else {
        matches = this.findMatches(fileContent.content, pattern);
      }
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework, hasSecurityMeasures, issues.length);
        
        // Skips if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validates the AI code issue
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

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, hasSecurityMeasures?: boolean, issueCount?: number): AiCodeContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language),
      isInString: this.isInString(currentLine, column),
      isInTestFile: this.isInTestFile(fileContent.path),
      isInDocumentation: this.isInDocumentation(fileContent.path),
      isInDevelopment: this.isInDevelopment(surroundingLines),
      isInCommitLog: this.isInCommitLog(surroundingLines),
      isInLicenseHeader: this.isInLicenseHeader(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      hasSecurityMeasures: hasSecurityMeasures || false,
      issueCount: issueCount || 0
    };
  }

  private isSafeContext(context: AiCodeContext): boolean {
  
    if (context.isInComment) return true;
    
    if (context.isInTestFile) return true;
  
    if (context.isInDocumentation) return true;

    if (context.isInDevelopment) return true;
 
    if (context.isInCommitLog) return true;
   
    if (context.isInLicenseHeader) return true;
    
    if (this.falsePositivePatterns.some(pattern => pattern.test(context.surroundingCode))) {
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
      'cs': 'csharp'
    };
    return languageMap[ext || ''] || 'unknown';
  }

  private detectFramework(content: string, language: string): string | undefined {
    if (language === 'javascript' || language === 'typescript') {
      if (content.includes('react') || content.includes('React')) return 'react';
      if (content.includes('vue') || content.includes('Vue')) return 'vue';
      if (content.includes('angular') || content.includes('Angular')) return 'angular';
      if (content.includes('express') || content.includes('Express')) return 'express';
    }
    if (language === 'python') {
      if (content.includes('django') || content.includes('Django')) return 'django';
      if (content.includes('flask') || content.includes('Flask')) return 'flask';
      if (content.includes('fastapi') || content.includes('FastAPI')) return 'fastapi';
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

  private isInCommitLog(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('commit') || 
      line.includes('git') ||
      line.includes('svn') ||
      line.includes('version') ||
      line.includes('changelog') ||
      line.includes('history')
    );
  }

  private isInLicenseHeader(lines: string[]): boolean {
    return lines.some(line => 
      line.includes('license') || 
      line.includes('copyright') ||
      line.includes('MIT') ||
      line.includes('Apache') ||
      line.includes('GPL') ||
      line.includes('BSD')
    );
  }

  private hasSecurityMeasures(content: string): boolean {
    const securityPatterns = [
      /validate/i,
      /review/i,
      /secure/i,
      /safe/i,
      /sanitize/i,
      /escape/i,
      /filter/i,
      /protect/i,
      /audit/i,
      /scan/i
    ];
    return securityPatterns.some(pattern => pattern.test(content));
  }

  private calculateConfidence(baseConfidence: number, context: AiCodeContext): number {
    let confidence = baseConfidence;
    
    // Adjusts confidence based on context
    if (context.hasSecurityMeasures) confidence *= 0.7; // Reduces if security measures present
    if (context.framework) confidence *= 1.1; // Increases for known frameworks
    
    return Math.min(confidence, 1.0);
  }

  private calculateSeverity(baseSeverity: 'critical' | 'high' | 'medium', context: AiCodeContext): 'critical' | 'high' | 'medium' {
    let severity = baseSeverity;
    
    // Auto escalates severity if multiple issues found
    if (context.issueCount > 2) {
      if (severity === 'medium') severity = 'high';
      if (severity === 'high') severity = 'critical';
    }
    
    // Reduces severity in development context
    if (context.isInDevelopment) {
      if (severity === 'critical') severity = 'high';
      if (severity === 'high') severity = 'medium';
    }
    
    return severity;
  }

  // Validation methods for different AI code issues!
  private validateAiGeneratedCode(text: string): boolean {
    const aiKeywords = ['generated', 'ai', 'copilot', 'chatgpt', 'gpt', 'claude'];
    return aiKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateUnvalidatedCode(text: string): boolean {
    const unvalidatedKeywords = ['unvalidated', 'unreviewed', 'unchecked'];
    return unvalidatedKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateNoReviewCode(text: string): boolean {
    const noReviewKeywords = ['no[_-]?review', 'without[_-]?review', 'skip[_-]?review'];
    return noReviewKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateVulnerableCode(text: string): boolean {
    const vulnerableKeywords = ['vulnerable', 'insecure', 'unsafe'];
    return vulnerableKeywords.some(keyword => text.toLowerCase().includes(keyword));
  }

  private validateSecurityBypass(text: string): boolean {
    const bypassKeywords = ['bypass', 'skip', 'ignore'];
    const securityKeywords = ['security', 'validation'];
    return bypassKeywords.some(bypass => text.toLowerCase().includes(bypass)) &&
           securityKeywords.some(security => text.toLowerCase().includes(security));
  }

  private validateEvalWithVariables(text: string): boolean {
    return text.includes('eval') && text.includes('${');
  }

  private validateSystemCommands(text: string): boolean {
    const systemKeywords = ['exec', 'system', 'spawn'];
    return systemKeywords.some(keyword => text.toLowerCase().includes(keyword)) && text.includes('${');
  }

  private validateSqlWithVariables(text: string): boolean {
    const sqlKeywords = ['query', 'sql'];
    return sqlKeywords.some(keyword => text.toLowerCase().includes(keyword)) && text.includes('${');
  }

  private validateMultiLineInjection(text: string): boolean {
    const injectionKeywords = ['ignore', 'forget', 'system', 'assistant', 'user'];
    const contextKeywords = ['previous', 'above', 'instructions'];
    return injectionKeywords.some(injection => text.toLowerCase().includes(injection)) &&
           contextKeywords.some(context => text.toLowerCase().includes(context));
  }

  private validateFileOperations(text: string): boolean {
    const fileKeywords = ['readFile', 'writeFile', 'fs.read', 'fs.write'];
    return fileKeywords.some(keyword => text.toLowerCase().includes(keyword)) && text.includes('${');
  }

  private validateNetworkRequests(text: string): boolean {
    const networkKeywords = ['fetch', 'axios', 'request'];
    return networkKeywords.some(keyword => text.toLowerCase().includes(keyword)) && text.includes('${');
  }

  private getLineContext(lineContent: string, column: number): string {
    const start = Math.max(0, column - 20);
    const end = Math.min(lineContent.length, column + 20);
    return lineContent.substring(start, end).trim();
  }

  private findMultiLineMatches(content: string, pattern: RegExp): Array<{
    match: RegExpMatchArray;
    line: number;
    column: number;
    lineContent: string;
  }> {
    const matches: Array<{
      match: RegExpMatchArray;
      line: number;
      column: number;
      lineContent: string;
    }> = [];
    
    let match: RegExpMatchArray | null;
    const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    
    while ((match = globalPattern.exec(content)) !== null) {
      // Finds the line number for the match
      const matchIndex = match.index ?? 0;
      const beforeMatch = content.substring(0, matchIndex);
      const lineNumber = beforeMatch.split('\n').length;
      const lineStart = beforeMatch.lastIndexOf('\n') + 1;
      const columnNumber = matchIndex - lineStart + 1;
      
      // Gets the line content (first line of multi line match)
      const lines = content.split('\n');
      const lineContent = lines[lineNumber - 1] || '';
      
      matches.push({
        match,
        line: lineNumber,
        column: columnNumber,
        lineContent
      });
      
      if (!pattern.flags.includes('g')) break;
    }
    
    return matches;
  }

  private generateSuggestion(type: string, context: AiCodeContext): string {
    const suggestions = {
      'AI-Generated Code': 'Implement mandatory code review for all AI-generated code. Use automated security scanning tools.',
      'Unvalidated AI Code': 'Establish validation processes for AI-generated code. Implement automated testing and security checks.',
      'AI Code Without Security Review': 'Require security review for all AI-generated code before deployment. Use static analysis tools.',
      'Vulnerable AI-Generated Code': 'Immediately review and fix vulnerabilities in AI-generated code. Implement secure coding practices.',
      'AI Code Bypassing Security': 'Remove security bypasses from AI-generated code. Implement proper security controls and validation.',
      'AI-Generated Eval with Variables': 'Replace eval() with safer alternatives. Use JSON.parse() or structured data handling.',
      'AI-Generated System Commands': 'Avoid system commands with user input. Use parameterized commands or built-in APIs.',
      'AI-Generated SQL with Variables': 'Use parameterized queries or ORM. Never concatenate user input into SQL strings.',
      'Multi-Line AI Injection': 'Implement input validation and sanitization. Use content filtering for AI prompts.',
      'AI-Generated File Operations': 'Validate file paths and implement access controls. Use safe file handling libraries.',
      'AI-Generated Network Requests': 'Validate URLs and implement request sanitization. Use secure HTTP libraries.'
    };
    
    let suggestion = suggestions[type as keyof typeof suggestions] || 'Implement comprehensive security review for AI-generated code. Use automated scanning and manual validation.';
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, consider using framework-specific security features and validation patterns.`;
      
      if (context.framework === 'react') {
        suggestion += ' Use React security best practices and avoid dangerous patterns like eval().';
      } else if (context.framework === 'django') {
        suggestion += ' Use Django security features and avoid raw SQL queries.';
      } else if (context.framework === 'express') {
        suggestion += ' Use Express security middleware and input validation.';
      }
    }
    
    if (context.issueCount > 2) {
      suggestion += ' Multiple AI-generated code issues detected. Consider implementing a comprehensive AI code review process.';
    }
    
    return suggestion;
  }
}