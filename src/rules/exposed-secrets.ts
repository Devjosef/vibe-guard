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
  isInDocumentation: boolean;
  isRepeatedSecret: boolean;
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
    
    // Azure
    { 
      pattern: /[A-Za-z0-9+\/=]{88}/g, 
      type: 'Azure Storage Key',
      confidence: 0.85,
      validation: (secret: string) => this.validateAzureKey(secret)
    },
    
    // Stripe
    { 
      pattern: /sk_live_[0-9a-zA-Z]{24}/g, 
      type: 'Stripe Live Secret Key',
      confidence: 0.95,
      validation: (secret: string) => this.validateStripeKey(secret)
    },
    { 
      pattern: /sk_test_[0-9a-zA-Z]{24}/g, 
      type: 'Stripe Test Secret Key',
      confidence: 0.8,
      validation: (secret: string) => this.validateStripeKey(secret)
    },
    
    // Twilio
    { 
      pattern: /SK[0-9a-fA-F]{32}/g, 
      type: 'Twilio Secret Key',
      confidence: 0.9,
      validation: (secret: string) => this.validateTwilioKey(secret)
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
    
    // RSA/SSH Private Keys
    { 
      pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[a-zA-Z0-9+\/=\s]+-----END (?:RSA |EC |DSA )?PRIVATE KEY-----/g, 
      type: 'RSA/SSH Private Key',
      confidence: 0.95,
      validation: (secret: string) => this.validatePrivateKey(secret)
    },
    
    // Google OAuth Client Secrets
    { 
      pattern: /"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"/g, 
      type: 'Google OAuth Client Secret',
      confidence: 0.85,
      validation: (secret: string) => this.validateGoogleOAuth(secret)
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

  // Multi-line comment patterns
  private readonly multiLineCommentPatterns = [
    /\/\*[\s\S]*?\*\//g,  // JavaScript/TypeScript multi-line comments
    /""".*?"""/gs,        // Python docstrings
    /<!--.*?-->/gs,       // HTML comments
    /#\[\[.*?\]\]/gs,     // Lua multi-line comments
    /\/\*[\s\S]*?\*\//g,  // C/C++ multi-line comments
    /\/\*[\s\S]*?\*\//g   // Java multi-line comments
  ];

  check(fileContent: FileContent): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const language = this.detectLanguage(fileContent.path);
    const framework = this.detectFramework(fileContent.content, language);
    const isInDocumentation = this.isInDocumentation(fileContent.path);
    const repeatedSecrets = this.findRepeatedSecrets(fileContent.content);
    
    for (const { pattern, type, confidence, validation } of this.secretPatterns) {
      const matches = this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        const context = this.analyzeContext(fileContent, line, column, language, framework, isInDocumentation, repeatedSecrets);
        
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

  private analyzeContext(fileContent: FileContent, line: number, column: number, language: string, framework?: string, isInDocumentation?: boolean, repeatedSecrets?: Set<string>): SecretContext {
    const lines = fileContent.lines;
    const currentLine = lines[line - 1] || '';
    const surroundingLines = lines.slice(Math.max(0, line - 3), line + 2);
    
    return {
      isInComment: this.isInComment(currentLine, language, fileContent.content, line),
      isInString: this.isInString(currentLine, column),
      isInTemplate: this.isInTemplate(currentLine, language),
      isInObject: this.isInObject(currentLine),
      isInFunction: this.isInFunction(surroundingLines),
      surroundingCode: surroundingLines.join('\n'),
      language,
      framework,
      isInDocumentation: isInDocumentation || false,
      isRepeatedSecret: repeatedSecrets ? repeatedSecrets.has(currentLine) : false
    };
  }

  private isSafeContext(context: SecretContext): boolean {
    // Safe if in comment
    if (context.isInComment) return true;
    
    // Safe if in documentation
    if (context.isInDocumentation) return true;
    
    // Safe if repeated secret (likely test data)
    if (context.isRepeatedSecret) return true;
    
    // Safe if in documentation context
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

  private isInComment(line: string, language: string, fullContent: string, lineNumber: number): boolean {
    const trimmed = line.trim();
    
    // Check for single-line comments
    if (language === 'javascript' || language === 'typescript') {
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return true;
    }
    if (language === 'python') {
      if (trimmed.startsWith('#')) return true;
    }
    if (language === 'php') {
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('#')) return true;
    }
    
    // Check for multi-line comments
    const beforeContent = fullContent.split('\n').slice(0, lineNumber).join('\n');
    
    for (const pattern of this.multiLineCommentPatterns) {
      const matches = beforeContent.match(pattern);
      if (matches && matches.length > 0) {
        // Check if the current line is within a multi-line comment
        const lastMatch = matches[matches.length - 1];
        if (lastMatch) {
          const lastMatchIndex = beforeContent.lastIndexOf(lastMatch);
          const commentEndIndex = lastMatchIndex + lastMatch.length;
          
          // If we're still within the comment, return true
          if (commentEndIndex >= beforeContent.length) {
            return true;
          }
        }
      }
    }
    
    return false;
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

  private findRepeatedSecrets(content: string): Set<string> {
    const repeatedSecrets = new Set<string>();
    const secretLines = new Map<string, number>();
    
    // Extract all potential secret lines
    for (const { pattern } of this.secretPatterns) {
      const matches = this.findMatches(content, pattern);
      for (const { lineContent } of matches) {
        const normalizedLine = lineContent.trim();
        const count = secretLines.get(normalizedLine) || 0;
        secretLines.set(normalizedLine, count + 1);
      }
    }
    
    // Mark as repeated if appears more than 3 times
    for (const [line, count] of secretLines) {
      if (count > 3) {
        repeatedSecrets.add(line);
      }
    }
    
    return repeatedSecrets;
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
    if (context.isInDocumentation) confidence *= 0.5; // Reduce for documentation
    if (context.isRepeatedSecret) confidence *= 0.3; // Significantly reduce for repeated secrets
    
    return Math.min(confidence, 1.0);
  }

  // Entropy calculation for better generic secret validation
  private calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;
    
    const charCounts = new Map<string, number>();
    for (const char of str) {
      charCounts.set(char, (charCounts.get(char) || 0) + 1);
    }
    
    let entropy = 0;
    for (const count of charCounts.values()) {
      const probability = count / len;
      entropy -= probability * Math.log2(probability);
    }
    
    return entropy;
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

  private validateAzureKey(key: string): boolean {
    return /^[A-Za-z0-9+\/=]{88}$/.test(key);
  }

  private validateStripeKey(key: string): boolean {
    return /^sk_(live|test)_[0-9a-zA-Z]{24}$/.test(key);
  }

  private validateTwilioKey(key: string): boolean {
    return /^SK[0-9a-fA-F]{32}$/.test(key);
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

  private validatePrivateKey(key: string): boolean {
    return /^-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[a-zA-Z0-9+\/=\s]+-----END (?:RSA |EC |DSA )?PRIVATE KEY-----$/.test(key);
  }

  private validateGoogleOAuth(secret: string): boolean {
    return /^"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"$/.test(secret);
  }

  private validateGenericSecret(secret: string): boolean {
    // More sophisticated validation for generic secrets
    if (secret.length < 20) return false;
    
    // Check for entropy (improved)
    const entropy = this.calculateEntropy(secret);
    if (entropy < 3.5) return false; // Require minimum entropy
    
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
      'Azure Storage Key': 'Use Azure Key Vault or environment variables for Azure storage keys.',
      'Stripe Live Secret Key': 'Use Stripe webhook signing secrets and environment variables. Never commit live keys.',
      'Stripe Test Secret Key': 'Use environment variables for test keys as well.',
      'Twilio Secret Key': 'Use Twilio environment variables and secure key management.',
      'Slack Token': 'Use Slack app configuration or environment variables.',
      'JWT Token': 'Use secure token storage and environment variables for JWT secrets.',
      'RSA/SSH Private Key': 'Use SSH key management systems and never commit private keys to version control.',
      'Google OAuth Client Secret': 'Use environment variables for OAuth client secrets.',
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