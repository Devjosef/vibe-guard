import { BaseRule, FileContent, SecurityIssue } from '../types';

export class AiGeneratedCodeValidationRule extends BaseRule {
  readonly name = 'ai-generated-code-validation';
  readonly description = 'Detects security issues in AI-generated code and validates its safety';
  readonly severity = 'high' as const;

  private readonly aiCodePatterns = [
    { 
      pattern: /(?:generated[_-]?by|ai[_-]?generated|copilot|chatgpt|gpt[_-]?generated|claude[_-]?generated)/gi, 
      type: 'AI-Generated Code',
      severity: 'medium' as const
    },
    { 
      pattern: /(?:ai|generated|copilot).*?(?:unvalidated|unreviewed|unchecked)/gi, 
      type: 'Unvalidated AI Code',
      severity: 'high' as const
    },
    { 
      pattern: /(?:ai|generated|copilot).*?(?:no[_-]?review|without[_-]?review|skip[_-]?review)/gi, 
      type: 'AI Code Without Security Review',
      severity: 'high' as const
    },
    { 
      pattern: /(?:ai|generated|copilot).*?(?:vulnerable|insecure|unsafe)/gi, 
      type: 'Vulnerable AI-Generated Code',
      severity: 'critical' as const
    },
    { 
      pattern: /(?:ai|generated|copilot).*?(?:bypass|skip|ignore).*?(?:security|validation)/gi, 
      type: 'AI Code Bypassing Security',
      severity: 'critical' as const
    },
    {
      pattern: /(?:prompt|input).*?(?:ignore|forget|system|assistant|user).*?(?:previous|above|instructions)/gis,
      type: 'Multi-Line AI Injection',
      severity: 'critical' as const
    }
  ];

  private readonly falsePositivePatterns = [
    // Basic false positives
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
    
    // Security-related false positives
    /validate/i,
    /review/i,
    /secure/i,
    /safe/i,
    /sanitize/i,
    /escape/i,
    /filter/i,
    /protect/i,
    
    // Documentation and examples
    /documentation/i,
    /readme/i,
    /docs/i,
    /example[_-]?code/i,
    /sample[_-]?code/i,
    /demo[_-]?code/i,
    
    // Test files and directories
    /test[_-]?files?/i,
    /test[_-]?data/i,
    /test[_-]?cases/i,
    /spec[_-]?files?/i,
    /__tests__/i,
    /\.test\./i,
    /\.spec\./i,
    
    // Configuration and setup
    /config[_-]?example/i,
    /setup[_-]?example/i,
    /template[_-]?example/i,
    
    // Comments indicating safe usage
    /\/\/.*(?:safe|secure|validated|reviewed)/i,
    /#.*(?:safe|secure|validated|reviewed)/i,
    /\/\*.*(?:safe|secure|validated|reviewed).*\*\//i
  ];

  private readonly contextPatterns = [
    // Development environment indicators
    /NODE_ENV\s*[:=]\s*['"`]development['"`]/i,
    /process\.env\.NODE_ENV\s*[:=]\s*['"`]development['"`]/i,
    /DEBUG\s*[:=]\s*['"`]true['"`]/i,
    /debug\s*[:=]\s*true/i,
    
    // Test environment indicators
    /NODE_ENV\s*[:=]\s*['"`]test['"`]/i,
    /process\.env\.NODE_ENV\s*[:=]\s*['"`]test['"`]/i,
    /TESTING\s*[:=]\s*['"`]true['"`]/i,
    /testing\s*[:=]\s*true/i,
    
    // Local development indicators
    /localhost/i,
    /127\.0\.0\.1/i,
    /0\.0\.0\.0/i,
    /dev\./i,
    /staging\./i,
    /test\./i
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    const isDevelopmentContext = this.isDevelopmentContext(fileContent.content);
    const isTestFile = this.isTestFile(fileContent.path);

    for (const { pattern, type, severity } of this.aiCodePatterns) {
      let matches;
      
      // Handle multi line patterns differently
      if (pattern.flags.includes('s')) {
        matches = this.findMultiLineMatches(fileContent.content, pattern);
      } else {
        matches = this.findMatches(fileContent.content, pattern);
      }
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        
        // Enhanced false positive detection
        if (this.isFalsePositive(lineContent, matchedText, fileContent.path)) {
          continue;
        }

        // Context-aware severity adjustment
        let adjustedSeverity = severity;
        if (isDevelopmentContext || isTestFile) {
          adjustedSeverity = this.adjustSeverityForContext(severity);
        }

        
        if (adjustedSeverity === 'medium' && isDevelopmentContext) {
          continue;
        }

        issues.push(this.createIssue(
          fileContent.path,
          line,
          column,
          lineContent,
          `${adjustedSeverity.charAt(0).toUpperCase() + adjustedSeverity.slice(1)}: ${type} detected`,
          this.getSuggestion(type, isDevelopmentContext, isTestFile),
          adjustedSeverity
        ));
      }
    }

    return issues;
  }

  private isFalsePositive(lineContent: string, matchedText: string, filePath: string): boolean {
   
    if (this.falsePositivePatterns.some(pattern => pattern.test(lineContent))) {
      return true;
    }


    if (filePath.match(/\.(md|txt|rst|adoc)$/i)) {
      return true;
    }

    if (filePath.match(/\.(example|sample|template)\./i)) {
      return true;
    }

    if (lineContent.trim().startsWith('//') || lineContent.trim().startsWith('#') || 
        lineContent.trim().startsWith('/*') || lineContent.trim().startsWith('<!--')) {
      return true;
    }

    // Check for variable assignments that are clearly examples
    if (matchedText.match(/['"`](example|demo|test|sample|placeholder)['"`]/i) !== null) {
      return true;
    }

    return false;
  }

  private isDevelopmentContext(content: string): boolean {
    return this.contextPatterns.some(pattern => pattern.test(content));
  }

  private isTestFile(filePath: string): boolean {
    return filePath.includes('test') || 
           filePath.includes('spec') || 
           filePath.includes('__tests__') ||
           filePath.match(/\.(test|spec)\./i) !== null;
  }

  private adjustSeverityForContext(originalSeverity: 'critical' | 'high' | 'medium'): 'critical' | 'high' | 'medium' {
    switch (originalSeverity) {
      case 'critical':
        return 'high';
      case 'high':
        return 'medium';
      case 'medium':
        return 'medium'; // Keep medium as minimum
      default:
        return originalSeverity;
    }
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
      // Find the line number for the match
      const matchIndex = match.index ?? 0;
      const beforeMatch = content.substring(0, matchIndex);
      const lineNumber = beforeMatch.split('\n').length;
      const lineStart = beforeMatch.lastIndexOf('\n') + 1;
      const columnNumber = matchIndex - lineStart + 1;
      
      // Get the line content (first line of multi-line match)
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

  private getSuggestion(_type: string, isDevelopment: boolean, isTestFile: boolean): string {
    const baseSuggestion = `Always validate and review AI-generated code for security vulnerabilities. Implement automated security scanning and manual code review processes.`;
    
    if (isDevelopment) {
      return `${baseSuggestion} Consider using a separate security review process for production deployments.`;
    }
    
    if (isTestFile) {
      return `${baseSuggestion} Ensure test files don't contain production security bypasses.`;
    }
    
    return baseSuggestion;
  }
}