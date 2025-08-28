import { BaseRule, FileContent, SecurityIssue, SeverityLevel } from '../types';

interface SecretPattern {
  pattern: RegExp;
  type: string;
  confidence: number;
  validation: (secret: string) => boolean;
  multiLine?: boolean;
}

interface SecretContext {
  isInEnvFile: boolean;
  isInConfigFile: boolean;
  isInDocumentation: boolean;
  isInTestFile: boolean;
  isInExampleFile: boolean;
  framework?: string;
  language: string;
}

export class ExposedSecretsRule extends BaseRule {
  readonly name = 'exposed-secrets';
  readonly description = 'Detects exposed API keys, tokens, and credentials with context-aware analysis';
  readonly severity = 'critical' as const;

  private readonly secretPatterns: SecretPattern[] = [
    // Critical severity: AWS keys
    { 
      pattern: /AKIA[0-9A-Z]{16}/g, 
      type: 'AWS Access Key',
      confidence: 0.95,
      validation: (secret: string) => this.validateAwsKey(secret)
    },
    // High severity: AWS secrets
    { 
      pattern: /(?:aws[_-]?secret|AWS_SECRET)\s*[:=]\s*['"`]([a-zA-Z0-9/+=]{40})/gi, 
      type: 'AWS Secret',
      confidence: 0.9,
      validation: (secret: string) => this.validateAwsSecret(secret)
    },
    // Critical severity: GitHub tokens
    { 
      pattern: /ghp_[a-zA-Z0-9]{36}/g, 
      type: 'GitHub Personal Access Token',
      confidence: 0.95,
      validation: (secret: string) => this.validateGitHubToken(secret)
    },
    // Critical severity: GitHub app tokens
    { 
      pattern: /ghs_[a-zA-Z0-9]{36}/g, 
      type: 'GitHub App Token',
      confidence: 0.95,
      validation: (secret: string) => this.validateGitHubToken(secret)
    },
    // Critical severity: GitHub refresh tokens
    { 
      pattern: /ghr_[a-zA-Z0-9]{36}/g, 
      type: 'GitHub Refresh Token',
      confidence: 0.95,
      validation: (secret: string) => this.validateGitHubToken(secret)
    },
    // Critical severity: Google API keys
    { 
      pattern: /AIza[0-9A-Za-z_\-]{35}/g, 
      type: 'Google API Key',
      confidence: 0.9,
      validation: (secret: string) => this.validateGoogleKey(secret)
    },
    // High severity: Slack tokens
    { 
      pattern: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g, 
      type: 'Slack Token',
      confidence: 0.85,
      validation: (secret: string) => this.validateSlackToken(secret)
    },
    // Critical severity: Stripe live secret keys
    {
      pattern: /sk_live_[a-zA-Z0-9]{24}/g,
      type: 'Stripe Live Secret Key',
      confidence: 0.95,
      validation: (secret: string) => this.validateStripeKey(secret)
    },
    // High severity: Stripe test secret keys
    {
      pattern: /sk_test_[a-zA-Z0-9]{24}/g,
      type: 'Stripe Test Secret Key',
      confidence: 0.8,
      validation: (secret: string) => this.validateStripeKey(secret)
    },
    // Critical severity: Stripe live publishable keys
    {
      pattern: /pk_live_[a-zA-Z0-9]{24}/g,
      type: 'Stripe Live Publishable Key',
      confidence: 0.7,
      validation: (secret: string) => this.validateStripeKey(secret)
    },
    // Critical severity: Twilio secret keys
    {
      pattern: /SK[a-f0-9]{32}/g,
      type: 'Twilio Secret Key',
      confidence: 0.9,
      validation: (secret: string) => this.validateTwilioKey(secret)
    },
    // High severity: Twilio account SIDs
    {
      pattern: /AC[a-f0-9]{32}/g,
      type: 'Twilio Account SID',
      confidence: 0.85,
      validation: (secret: string) => this.validateTwilioSid(secret)
    },
    // Critical severity: SendGrid API keys
    {
      pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
      type: 'SendGrid API Key',
      confidence: 0.9,
      validation: (secret: string) => this.validateSendGridKey(secret)
    },
    // Critical severity: Azure service principals
    {
      pattern: /[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}/g,
      type: 'Azure Service Principal',
      confidence: 0.85,
      validation: (secret: string) => this.validateAzurePrincipal(secret)
    },
    // Critical severity: GCP service account keys
    {
      pattern: /"type":\s*"service_account".*"private_key_id":\s*"[a-zA-Z0-9]+"/gs,
      type: 'GCP Service Account Key',
      confidence: 0.95,
      validation: (secret: string) => this.validateGcpServiceAccount(secret),
      multiLine: true
    },
    // High severity: Heroku API keys
    {
      pattern: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
      type: 'Heroku API Key',
      confidence: 0.8,
      validation: (secret: string) => this.validateHerokuKey(secret)
    },
    // High severity: JWT tokens
    { 
      pattern: /eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*/g, 
      type: 'JWT Token',
      confidence: 0.8,
      validation: (secret: string) => this.validateJWT(secret)
    },
    // Critical severity: PEM private keys
    {
      pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----\s*[A-Za-z0-9+/=\s]+\s*-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
      type: 'PEM Private Key',
      confidence: 0.95,
      validation: (secret: string) => this.validatePemKey(secret),
      multiLine: true
    },
    // High severity: API keys
    { 
      pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, 
      type: 'API Key',
      confidence: 0.7,
      validation: (secret: string) => this.validateGenericSecret(secret)
    },
    // High severity: Secret keys
    { 
      pattern: /(?:secret[_-]?key|secretkey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})/gi, 
      type: 'Secret Key',
      confidence: 0.7,
      validation: (secret: string) => this.validateGenericSecret(secret)
    },
    // High severity: Access tokens
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
    const context = this.analyzeFileContext(fileContent.path);
    
    for (const { pattern, type, confidence, validation, multiLine } of this.secretPatterns) {
      const matches = multiLine ? 
        this.findMultiLineMatches(fileContent.content, pattern) :
        this.findMatches(fileContent.content, pattern);
      
      for (const { match, line, column, lineContent } of matches) {
        const matchedText = match[0];
        
        if (this.isSafeContext(context, matchedText)) {
          continue;
        }
        
        if (!validation(matchedText)) {
          continue;
        }
        
        const finalConfidence = this.calculateConfidence(confidence, context, type);
        const severity = this.determineSeverity(finalConfidence, context, type);
        
        if (finalConfidence >= 0.6) {
          issues.push(this.createIssue(
            fileContent.path,
            line,
            column,
            lineContent,
            `Exposed ${type} detected (confidence: ${Math.round(finalConfidence * 100)}%): ${this.maskSecret(matchedText)}`,
            this.generateSuggestion(type, context, framework),
            severity
          ));
        }
      }
    }

    return issues;
  }

  private analyzeFileContext(filePath: string): SecretContext {
    const lowerPath = filePath.toLowerCase();
    
    return {
      isInEnvFile: lowerPath.includes('.env') || lowerPath.includes('environment'),
      isInConfigFile: lowerPath.includes('config') || lowerPath.includes('.yml') || lowerPath.includes('.yaml') || lowerPath.includes('.json'),
      isInDocumentation: lowerPath.includes('readme') || lowerPath.includes('.md') || lowerPath.includes('docs'),
      isInTestFile: lowerPath.includes('test') || lowerPath.includes('spec') || lowerPath.includes('__tests__'),
      isInExampleFile: lowerPath.includes('example') || lowerPath.includes('sample') || lowerPath.includes('demo'),
      language: this.detectLanguage(filePath)
    };
  }

  private isSafeContext(context: SecretContext, secret: string): boolean {
    if (context.isInTestFile || context.isInExampleFile) {
      return false;
    }
    
    if (context.isInDocumentation) {
      return true;
    }
    
    if (this.hasTestPrefix(secret)) {
      return true;
    }
    
    return false;
  }

  private hasTestPrefix(secret: string): boolean {
    const testPrefixes = ['test-', 'demo-', 'example-', 'sample-', 'dev-', 'staging-'];
    return testPrefixes.some(prefix => secret.toLowerCase().startsWith(prefix));
  }

  private calculateConfidence(baseConfidence: number, context: SecretContext, type: string): number {
    let confidence = baseConfidence;
    
    if (type === 'JWT Token' && (context.isInTestFile || context.isInExampleFile)) {
      confidence *= 0.5;
    }
    
    if (context.isInEnvFile || context.isInConfigFile) {
      confidence *= 1.2;
    }
    
    if (context.isInDocumentation) {
      confidence *= 0.3;
    }
    
    return Math.min(confidence, 1.0);
  }

  private determineSeverity(confidence: number, context: SecretContext, type: string): SeverityLevel {
    if ((context.isInEnvFile || context.isInConfigFile) && confidence >= 0.8) {
      return 'critical';
    }
    
    if (context.isInDocumentation) {
      return 'medium';
    }
    
    if (type === 'JWT Token' && (context.isInTestFile || context.isInExampleFile)) {
      return 'medium';
    }
    
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.7) return 'high';
    return 'medium';
  }

  private findMultiLineMatches(content: string, pattern: RegExp): Array<{ match: RegExpMatchArray; line: number; column: number; lineContent: string }> {
    const matches: Array<{ match: RegExpMatchArray; line: number; column: number; lineContent: string }> = [];
    const lines = content.split('\n');
    
    const fullMatch = content.match(pattern);
    if (fullMatch) {
      const matchIndex = content.indexOf(fullMatch[0]);
      const linesBeforeMatch = content.substring(0, matchIndex).split('\n').length - 1;
      const lineNumber = linesBeforeMatch + 1;
      const lineContent = lines[lineNumber - 1] || '';
      
      matches.push({
        match: fullMatch as RegExpMatchArray,
        line: lineNumber,
        column: 1,
        lineContent
      });
    }
    
    return matches;
  }

  // Validation methods: Expanded coverage
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

  private validateStripeKey(key: string): boolean {
    return /^sk_(live|test)_[a-zA-Z0-9]{24}$/.test(key) || /^pk_(live|test)_[a-zA-Z0-9]{24}$/.test(key);
  }

  private validateTwilioKey(key: string): boolean {
    return /^SK[a-f0-9]{32}$/.test(key);
  }

  private validateTwilioSid(sid: string): boolean {
    return /^AC[a-f0-9]{32}$/.test(sid);
  }

  private validateSendGridKey(key: string): boolean {
    return /^SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}$/.test(key);
  }

  private validateAzurePrincipal(principal: string): boolean {
    return /^[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}$/.test(principal);
  }

  private validateGcpServiceAccount(content: string): boolean {
    return content.includes('"type": "service_account"') && content.includes('"private_key_id"');
  }

  private validateHerokuKey(key: string): boolean {
    return /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(key);
  }

  private validateJWT(token: string): boolean {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return false;
      
      return parts.every(part => /^[A-Za-z0-9_\-]+$/.test(part));
    } catch {
      return false;
    }
  }

  private validatePemKey(key: string): boolean {
    return key.includes('-----BEGIN') && key.includes('-----END') && key.includes('PRIVATE KEY');
  }

  private validateGenericSecret(secret: string): boolean {
    if (secret.length < 20) return false;
    
    const uniqueChars = new Set(secret).size;
    if (uniqueChars < 15) return false;
    
    if (/^(.)\1+$/.test(secret)) return false;
    if (/^(012|123|234|345|456|567|678|789|890)+$/.test(secret)) return false;
    
    if (this.hasTestPrefix(secret)) return false;
    
    const charTypes = {
      lowercase: /[a-z]/.test(secret),
      uppercase: /[A-Z]/.test(secret),
      numbers: /[0-9]/.test(secret),
      special: /[^a-zA-Z0-9]/.test(secret)
    };
    
    const typeCount = Object.values(charTypes).filter(Boolean).length;
    if (typeCount < 2) return false;
    
    return true;
  }

  private generateSuggestion(type: string, context: SecretContext, framework?: string): string {
    const baseSuggestions = {
      'AWS Access Key': 'Use AWS IAM roles or environment variables. Never commit AWS credentials to version control.',
      'AWS Secret': 'Use AWS Secrets Manager or environment variables for AWS secrets.',
      'GitHub Personal Access Token': 'Use GitHub Actions secrets or environment variables. Rotate tokens regularly.',
      'GitHub App Token': 'Use GitHub App installation tokens or environment variables.',
      'GitHub Refresh Token': 'Use GitHub OAuth refresh tokens securely.',
      'Google API Key': 'Restrict API key usage and use environment variables.',
      'Slack Token': 'Use Slack app configuration or environment variables.',
      'Stripe Live Secret Key': 'Use Stripe webhook endpoints and environment variables for live keys.',
      'Stripe Test Secret Key': 'Use environment variables for test keys.',
      'Stripe Live Publishable Key': 'Publishable keys are safe to expose but should be restricted.',
      'Twilio Secret Key': 'Use Twilio environment variables or secure storage.',
      'Twilio Account SID': 'Use environment variables for Twilio credentials.',
      'SendGrid API Key': 'Use SendGrid environment variables or secure storage.',
      'Azure Service Principal': 'Use Azure Key Vault or environment variables.',
      'GCP Service Account Key': 'Use Google Cloud IAM roles or secure storage.',
      'Heroku API Key': 'Use Heroku environment variables or secure storage.',
      'JWT Token': 'Use secure token storage and environment variables for JWT secrets.',
      'PEM Private Key': 'Use secure key storage and never commit private keys.',
      'API Key': 'Use environment variables or secure secret management systems.',
      'Secret Key': 'Use environment variables or secure secret management systems.',
      'Access Token': 'Use environment variables or secure token management systems.'
    };
    
    let suggestion = baseSuggestions[type as keyof typeof baseSuggestions] || 'Use environment variables or secure secret management.';
    
    suggestion += ' **Rotate the secret immediately and purge from git history.**';
    
    if (context.isInEnvFile) {
      suggestion += ' Move secrets to a secure environment variable management system.';
    } else if (context.isInConfigFile) {
      suggestion += ' Use configuration management tools that support encrypted secrets.';
    } else if (context.isInDocumentation) {
      suggestion += ' Remove secrets from documentation and use placeholder examples.';
    }
    
    if (framework) {
      suggestion += ` For ${framework}, consider using framework-specific secret management.`;
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
}
