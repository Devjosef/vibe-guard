import { BaseRule, FileContent, SecurityIssue } from '../types';

interface SecretContext {
  isInComment: boolean;
  isInString: boolean;
  isInTemplate: boolean;
  isInObject: boolean;
  isInFunction: boolean;
  surroundingCode: string;
  language: string;
  framework: string | undefined;
}

export class ExposedSecretsRule extends BaseRule {
  readonly name = 'exposed-secrets';
  readonly description = 'Detects exposed API keys, tokens, and credentials with context-aware analysis';
  readonly severity = 'critical' as const;

  private readonly secretPatterns = [
    // AWS
    { 
      pattern: /AKIA[0-9A-Z]{16}/g, 
      type: 'AWS Access Key',
      confidence: 0.95,
      validation: (secret: string) => this.validateAwsKey(secret)
    },
    { 
      pattern: /(?:aws[_-]?secret|AWS_SECRET)\s*[:=]\s*['"`]([a-zA-Z0-9/+=]{40})/gi, 
      type: 'AWS Secret',
      confidence: 0.9,
      validation: (secret: string) => this.validateAwsSecret(secret)
    },
    
    // GitHub
    { 
      pattern: /ghp_[a-zA-Z0-9]{36}/g, 
      type: 'GitHub Personal Access Token',
      confidence: 0.95,
      validation: (secret: string) => this.validateGitHubToken(secret)
    },
    { 
      pattern: /ghs_[a-zA-Z0-9]{36}/g, 
      type: 'GitHub App Token',
      confidence: 0.95,
      validation: (secret: string) => this.validateGitHubToken(secret)
    },
    { 
      pattern: /ghr_[a-zA-Z0-9]{36}/g, 
      type: 'GitHub Refresh Token',
      confidence: 0.95,
      validation: (secret: string) => this.validateGitHubToken(secret)
    },
    
    // Google
    { 
      pattern: /AIza[0-9A-Za-z_\-]{35}/g, 
      type: 'Google API Key',
      confidence: 0.9,
      validation: (secret: string) => this.validateGoogleKey(secret)
    },
    
    // Slack
    { 
      pattern: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g, 
      type: 'Slack Token',
      confidence: 0.85,
      validation: (secret: string) => this.validateSlackToken(secret)
    },
    
    // JWT
    { 
      pattern: /eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*/g, 
      type: 'JWT Token',
      confidence: 0.8,
      validation: (secret: string) => this.validateJWT(secret)
    },
    
    // Generic patterns with lower confidence
    { 
      pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, 
      type: 'API Key',
      confidence: 0.7,
      validation: (secret: string) => this.validateGenericSecret(secret)
    },
    { 
      pattern: /(?:secret[_-]?key|secretkey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, 
      type: 'Secret Key',
      confidence: 0.7,
      validation: (secret: string) => this.validateGenericSecret(secret)
    },
    { 
      pattern: /(?:access[_-]?token|accesstoken)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, 
      type: 'Access Token',
      confidence: 0.7,
      validation: (secret: string) => this.validateGenericSecret(secret)
    }
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    
    for (const { pattern, type, confidence, validation } of this.secretPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework);
        
        // Skip if in safe context
        if (this.isSafeContext(context)) {
          continue;
        }
        
        // Validate the secret
        if (!validation(matchedText)) {
          continue;
        }
        
        // Calculate final confidence based on context
        const finalConfidence = this.calculateConfidence(confidence, context);
        
        if (finalConfidence >= 0.6) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `Exposed ${type} detected (confidence: ${Math.round(finalConfidence * 100)}%): ${this.maskSecret(matchedText)}`,
            this.generateSuggestion(type, context),
            finalConfidence >= 0.9 ? 'critical' : finalConfidence >= 0.7 ? 'high' : 'medium'
          ));
        }
      }
    }

    return issues;
  }

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string): SecretContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language),
      isInString: this.isInString(currentLine, column),
      isInTemplate: this.isInTemplate(currentLine, language),
      isInObject: this.isInObject(currentLine),
      isInFunction: this.isInFunction(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework
    };
  }

  private isSafeContext(context: SecretContext): boolean {
    // Safe if in comment
    if (context.isInComment) return true;
    
    // Safe if in documentation
    if (context.surroundingCode.includes('@example') || 
        context.surroundingCode.includes('TODO') ||
        context.surroundingCode.includes('FIXME')) {
      return true;
    }
    
    // Safe if in test files
    if (context.surroundingCode.includes('test') || 
        context.surroundingCode.includes('spec') ||
        context.surroundingCode.includes('mock')) {
      return true;
    }
    
    // Safe if using environment variables
    if (context.surroundingCode.includes('process.env') ||
        context.surroundingCode.includes('os.environ') ||
        context.surroundingCode.includes('getenv')) {
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
    }
    if (language === 'python') {
      if (content.includes('flask') || content.includes('Flask')) return 'flask';
      if (content.includes('django') || content.includes('Django')) return 'django';
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
    // Simple heuristic - could be improved with proper parsing
    const before = line.substring(0, column);
    const quotes = (before.match(/['"`]/g) || []).length;
    return quotes % 2 === 1;
  }

  private isInTemplate(line: string, language: string): boolean {
    return language === 'javascript' && line.includes('`') && line.includes('${');
  }

  private isInObject(line: string): boolean {
    return line.includes('{') && line.includes('}') && line.includes(':');
  }

  private isInFunction(lines: string[]): boolean {
    return lines.some(line => line.includes('function') || line.includes('=>') || line.includes('def '));
  }

  private calculateConfidence(baseConfidence: number, context: SecretContext): number {
    let confidence = baseConfidence;
    
    // Reduce confidence for certain contexts
    if (context.isInTemplate) confidence *= 0.8;
    if (context.isInObject) confidence *= 0.9;
    if (context.framework) confidence *= 1.1; // Slightly increase for known frameworks
    
    return Math.min(confidence, 1.0);
  }

  // Validation methods for different secret types
  private validateAwsKey(key: string): boolean {
    return /^AKIA[0-9A-Z]{16}$/.test(key);
  }

  private validateAwsSecret(secret: string): boolean {
    return /^[A-Za-z0-9/+=]{40}$/.test(secret);
  }

  private validateGitHubToken(token: string): boolean {
    return /^gh[psr]_[a-zA-Z0-9]{36}$/.test(token);
  }

  private validateGoogleKey(key: string): boolean {
    return /^AIza[0-9A-Za-z_\-]{35}$/.test(key);
  }

  private validateSlackToken(token: string): boolean {
    return /^xox[baprs]-[0-9a-zA-Z\-]{10,}$/.test(token);
  }

  private validateJWT(token: string): boolean {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return false;
      
      // Basic JWT structure validation
      return parts.every(part => /^[A-Za-z0-9_\-]+$/.test(part));
    } catch {
      return false;
    }
  }

  private validateGenericSecret(secret: string): boolean {
    // More sophisticated validation for generic secrets
    if (secret.length < 20) return false;
    
    // Check for entropy (basic)
    const uniqueChars = new Set(secret).size;
    if (uniqueChars < 10) return false;
    
    // Check for common patterns
    if (/^(.)\1+$/.test(secret)) return false;
    if (/^(012|123|234|345|456|567|678|789|890)+$/.test(secret)) return false;
    
    return true;
  }

  private generateSuggestion(type: string, context: SecretContext): string {
    const suggestions = {
      'AWS Access Key': 'Use AWS IAM roles or environment variables. Never commit AWS credentials to version control.',
      'AWS Secret': 'Use AWS Secrets Manager or environment variables for AWS secrets.',
      'GitHub Personal Access Token': 'Use GitHub Actions secrets or environment variables. Rotate tokens regularly.',
      'Google API Key': 'Restrict API key usage and use environment variables.',
      'Slack Token': 'Use Slack app configuration or environment variables.',
      'JWT Token': 'Use secure token storage and environment variables for JWT secrets.',
      'API Key': 'Use environment variables or secure secret management systems.',
      'Secret Key': 'Use environment variables or secure secret management systems.',
      'Access Token': 'Use environment variables or secure token management systems.'
    };
    
    let suggestion = suggestions[type as keyof typeof suggestions] || 'Use environment variables or secure secret management.';
    
    if (context.framework) {
      suggestion += ` For ${context.framework}, consider using framework-specific secret management.`;
    }
    
    return suggestion;
  }

  private maskSecret(secret: string): string {
    if (secret.length <= 8) {
      return '*'.repeat(secret.length);
    }
    
    const start = secret.substring(0, 4);
    const end = secret.substring(secret.length - 4);
    const middle = '*'.repeat(Math.min(secret.length - 8, 10));
    
    return `${start}${middle}${end}`;
  }
}